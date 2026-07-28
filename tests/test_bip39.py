"""BIP-39 against its own published vectors, and against a live node's answers.

Tier A throughout: `astral.bip39` is layer 1, so nothing here needs an event
loop and nothing here may need a node.

Three independent authorities, and the module has to satisfy all three:

- **The standard.** The entropy/mnemonic/seed triples below are the published
  BIP-39 English vectors, seeds taken under the passphrase `TREZOR` the vector
  file uses. A wrong bit anywhere in the checksum, the 11-bit packing or the
  PBKDF2 parameters moves the seed, and PBKDF2 does not collide by accident.
- **The wordlist.** `WORDLIST_SHA256` is the digest BIP-39 publishes for
  `english.txt`. It is computed here from `WORDLIST`, because a mistyped word is
  silent -- every mnemonic that contains it derives a wrong seed and nothing
  reports a fault -- and because the list ships as source in this repository
  rather than as a package with its own integrity.
- **The node.** `furry-bolt` answered `5eb00bbd…` for the all-zero mnemonic with
  no passphrase and `c55257c3…` under `TREZOR` this session; both are asserted
  below. astrald and this module are two implementations, and the seed is the
  one value a caller cannot check by eye.

**The normalisation pair is a defect vector, not a curiosity.** BIP-39 requires
NFKD before PBKDF2. astral-go omits it, so the node answered two different seeds
for two spellings of one passphrase -- both captured here -- and only the
normalised one is the seed BIP-39 defines. `astral.bip39` normalises, so the
first constant is what it produces and the second is what a caller who sends an
unnormalised passphrase to `bip137sig.seed` gets instead.
"""

from __future__ import annotations

import hashlib
import inspect
import unittest

from astral import bip39
from astral.errors import AstralError, BadArgument, BadArgumentType, ParseError

# --- the published vectors -----------------------------------------------

ZERO_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])

VECTORS = (
    (
        "00000000000000000000000000000000",
        ZERO_MNEMONIC,
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f"
        "09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice "
        "cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa2"
        "80f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332"
        "572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    ),
    (
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight "
        "picnic",
        "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c9"
        "1689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
    ),
    (
        "000000000000000000000000000000000000000000000000",
        " ".join(["abandon"] * 17 + ["agent"]),
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06d"
        "a5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        " ".join(["abandon"] * 23 + ["art"]),
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
        "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    ),
)
"""`(entropy hex, mnemonic, seed hex under "TREZOR")`, from the BIP-39 vectors."""

LIVE_ZERO_SEED = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5"
    "ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)
"""What `furry-bolt` answered for `ZERO_MNEMONIC` with no passphrase."""

NFKD_PASSPHRASE = "e\u0301"
"""`e` plus a combining acute: the NFKD form of `é`.

Written as an escape rather than as the character. The two spellings render
identically, so an editor or a tool that normalises this file on save would
collapse the pair into one value and leave every normalisation assertion
passing while testing nothing. `LiteralTest` asserts they are two strings."""

NFC_PASSPHRASE = "\u00e9"
"""The same `é` as one code point: NFC, and NFKD-equivalent to the above."""

NFKD_SEED = (
    "f37f8652bf7004d4bd4ba7702e70e647f54965758656423dde58d64fa725c1e8be1"
    "b0416864e10f714c0730e46f9676079b4fd4f72fcf0c09a120ae65589c091"
)
"""The BIP-39 seed of `ZERO_MNEMONIC` under `é`, from either spelling of it.
The node answers this one only when it is handed the NFKD form."""

UNNORMALISED_SEED = (
    "8382db9467ed68b6e4b0df26f05c04244ba9c665473060dbd7fd44df6db812b2615"
    "00dc134df1efab51c29d9a4ab8bd01053cd477980b333c7c7b4d0cf73731b"
)
"""What `furry-bolt` answered for the NFC spelling: not a BIP-39 seed at all,
and the whole of astral-go defect G-BIP39-NFKD in one constant."""


# --- the wordlist ---------------------------------------------------------


class WordlistTest(unittest.TestCase):
    """The 2048 words, checked against the digest BIP-39 publishes."""

    def test_the_wordlist_matches_the_published_digest(self):
        """`sha256(english.txt)`: the words, one per line, trailing newline. A
        single mistyped word derives a wrong seed for every mnemonic that
        contains it and reports nothing."""
        body = "\n".join(bip39.WORDLIST) + "\n"
        self.assertEqual(
            hashlib.sha256(body.encode("utf-8")).hexdigest(), bip39.WORDLIST_SHA256
        )

    def test_the_wordlist_holds_two_to_the_eleven_words(self):
        self.assertEqual(len(bip39.WORDLIST), 2**bip39.WORD_BITS)
        self.assertEqual(len(bip39.WORDLIST), 2048)

    def test_every_word_is_unique(self):
        """Index is meaning: a repeated word makes one index unreachable and
        makes decoding ambiguous."""
        self.assertEqual(len(set(bip39.WORDLIST)), len(bip39.WORDLIST))

    def test_every_word_is_lowercase_ascii(self):
        for word in bip39.WORDLIST:
            with self.subTest(word=word):
                self.assertTrue(word.isascii())
                self.assertTrue(word.islower())
                self.assertTrue(word.isalpha())

    def test_the_index_maps_every_word_to_its_position(self):
        self.assertEqual(len(bip39.WORD_INDEX), len(bip39.WORDLIST))
        self.assertEqual(bip39.WORD_INDEX["abandon"], 0)
        self.assertEqual(bip39.WORD_INDEX["zoo"], 2047)
        for index, word in enumerate(bip39.WORDLIST):
            if index % 97 == 0:
                self.assertEqual(bip39.WORD_INDEX[word], index)

    def test_the_first_four_letters_are_unique(self):
        """BIP-39's own property: four letters identify a word, which is why a
        truncated backup is still readable."""
        self.assertEqual(len({word[:4] for word in bip39.WORDLIST}), 2048)


class ConstantsTest(unittest.TestCase):
    """The sizes BIP-39 fixes, derived rather than copied."""

    def test_the_entropy_sizes_are_the_bit_sizes_in_bytes(self):
        self.assertEqual(bip39.ENTROPY_BITS, (128, 160, 192, 224, 256))
        self.assertEqual(bip39.ENTROPY_SIZES, (16, 20, 24, 28, 32))

    def test_the_word_counts_follow_from_the_entropy_sizes(self):
        """`(ENT + ENT/32) / 11`, which is astral-go's
        `ErrInvalidMnemonicWordCount` list."""
        self.assertEqual(bip39.WORD_COUNTS, (12, 15, 18, 21, 24))

    def test_the_pbkdf2_parameters_are_the_standard_ones(self):
        self.assertEqual(bip39.PBKDF2_ROUNDS, 2048)
        self.assertEqual(bip39.SEED_LENGTH, 64)
        self.assertEqual(bip39.SALT_PREFIX, "mnemonic")

    def test_the_default_entropy_size_is_the_node_s_default(self):
        """astral-go's `DefaultEntropyBits`. Verified live: an absent `bits`
        and `bits=0` both answer 16 bytes."""
        self.assertEqual(bip39.DEFAULT_ENTROPY_BITS, 128)

    def test_the_module_is_layer_one_and_names_no_event_loop(self):
        """Design section 1's hard rule: no asyncio import may reach layer 1."""
        source = inspect.getsource(bip39)
        self.assertNotIn("asyncio", source)


# --- entropy --------------------------------------------------------------


class NewEntropyTest(unittest.TestCase):
    def test_every_defined_size_produces_that_many_bytes(self):
        for bits in bip39.ENTROPY_BITS:
            with self.subTest(bits=bits):
                self.assertEqual(len(bip39.new_entropy(bits)), bits // 8)

    def test_the_default_is_sixteen_bytes(self):
        self.assertEqual(len(bip39.new_entropy()), 16)

    def test_two_calls_do_not_agree(self):
        """A CSPRNG, not a counter. The odds of a false failure are 2**-128."""
        self.assertNotEqual(bip39.new_entropy(), bip39.new_entropy())

    def test_a_size_bip39_does_not_define_is_refused(self):
        for bits in (0, 127, 129, 160 + 1, 512, -128):
            with self.subTest(bits=bits):
                with self.assertRaises(BadArgument):
                    bip39.new_entropy(bits)

    def test_a_bool_is_not_a_size(self):
        """`True == 1` in Python and `1` is not an entropy size, so this would
        have failed anyway; it is refused as a type so the message says so."""
        with self.assertRaises(BadArgumentType):
            bip39.new_entropy(True)  # type: ignore[arg-type]

    def test_a_non_integer_size_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            bip39.new_entropy("128")  # type: ignore[arg-type]


class ValidateEntropyTest(unittest.TestCase):
    """The rule `bip137sig.entropy` enforces on encode and on decode."""

    def test_every_defined_length_passes_and_returns_bytes(self):
        for size in bip39.ENTROPY_SIZES:
            with self.subTest(size=size):
                self.assertEqual(bip39.validate_entropy(bytes(size)), bytes(size))

    def test_a_length_off_the_step_is_refused(self):
        for size in (0, 15, 17, 18, 31, 33, 64):
            with self.subTest(size=size):
                with self.assertRaises(ParseError) as caught:
                    bip39.validate_entropy(bytes(size))
                self.assertIn("bip137sig.entropy", str(caught.exception))

    def test_a_bytearray_and_a_memoryview_are_accepted(self):
        self.assertEqual(bip39.validate_entropy(bytearray(16)), bytes(16))
        self.assertEqual(bip39.validate_entropy(memoryview(bytes(20))), bytes(20))

    def test_hex_text_is_refused_as_a_type(self):
        """`"00" * 16` is 32 characters and would silently be a 32-byte
        entropy, which is a different mnemonic."""
        with self.assertRaises(BadArgumentType) as caught:
            bip39.validate_entropy("00" * 16)  # type: ignore[arg-type]
        self.assertIn("fromhex", str(caught.exception))


# --- mnemonics ------------------------------------------------------------


class MnemonicTest(unittest.TestCase):
    def test_every_published_vector_round_trips(self):
        for entropy_hex, mnemonic, _ in VECTORS:
            with self.subTest(entropy=entropy_hex):
                entropy = bytes.fromhex(entropy_hex)
                self.assertEqual(
                    " ".join(bip39.entropy_to_mnemonic(entropy)), mnemonic
                )
                self.assertEqual(bip39.mnemonic_to_entropy(mnemonic), entropy)

    def test_each_entropy_size_produces_its_word_count(self):
        for size, count in zip(bip39.ENTROPY_SIZES, bip39.WORD_COUNTS):
            with self.subTest(size=size):
                self.assertEqual(len(bip39.entropy_to_mnemonic(bytes(size))), count)

    def test_a_random_mnemonic_round_trips_at_every_size(self):
        for bits in bip39.ENTROPY_BITS:
            with self.subTest(bits=bits):
                entropy = bip39.new_entropy(bits)
                words = bip39.entropy_to_mnemonic(entropy)
                self.assertEqual(bip39.mnemonic_to_entropy(words), entropy)

    def test_the_checksum_makes_the_last_word_depend_on_the_entropy(self):
        """`abandon` twelve times is twelve valid words and not a mnemonic: the
        last word carries four bits of `sha256(entropy)`."""
        self.assertEqual(bip39.entropy_to_mnemonic(bytes(16))[-1], "about")
        with self.assertRaises(ParseError) as caught:
            bip39.mnemonic_to_entropy(" ".join(["abandon"] * 12))
        self.assertIn("checksum", str(caught.exception))

    def test_an_unknown_word_names_itself_and_its_position(self):
        """astrald answers `invalid mnemonic` for this and for a bad checksum
        alike, verified live; the two have different fixes."""
        broken = ZERO_MNEMONIC.replace("about", "notaword")
        with self.assertRaises(ParseError) as caught:
            bip39.mnemonic_to_entropy(broken)
        self.assertIn("notaword", str(caught.exception))
        self.assertIn("12", str(caught.exception))

    def test_a_capitalised_word_is_not_in_the_wordlist(self):
        """Matching is exact, as `slices.Index(wordlist, word)` is. Verified
        live: `Abandon abandon … about` answers `invalid mnemonic`."""
        with self.assertRaises(ParseError):
            bip39.mnemonic_to_entropy("Abandon " + " ".join(["abandon"] * 10) + " about")

    def test_a_word_count_bip39_does_not_define_is_refused(self):
        for count in (0, 11, 13, 23, 25):
            with self.subTest(count=count):
                with self.assertRaises(ParseError) as caught:
                    bip39.mnemonic_to_entropy(["abandon"] * count)
                self.assertIn("words", str(caught.exception))

    def test_the_predicate_form_answers_rather_than_raising(self):
        self.assertTrue(bip39.is_valid_mnemonic(ZERO_MNEMONIC))
        self.assertFalse(bip39.is_valid_mnemonic(" ".join(["abandon"] * 12)))
        self.assertFalse(bip39.is_valid_mnemonic("nonsense"))

    def test_the_predicate_form_still_refuses_the_wrong_python_type(self):
        """A mnemonic of the wrong type is a caller fault, not a false
        mnemonic, and answering `False` would hide it."""
        with self.assertRaises(BadArgumentType):
            bip39.is_valid_mnemonic([1, 2, 3])  # type: ignore[list-item]


class WordsOfTest(unittest.TestCase):
    """Splitting, which the node does with `strings.Fields`."""

    def test_a_string_splits_on_any_whitespace(self):
        self.assertEqual(len(bip39.words_of(ZERO_MNEMONIC)), 12)
        self.assertEqual(
            bip39.words_of("\n".join(["abandon"] * 11 + ["about"])),
            bip39.words_of(ZERO_MNEMONIC),
        )
        self.assertEqual(
            bip39.words_of("  " + ZERO_MNEMONIC + "\t\n"),
            bip39.words_of(ZERO_MNEMONIC),
        )

    def test_a_sequence_joins_and_then_splits(self):
        """A sequence element holding a space is two words on the node too."""
        self.assertEqual(bip39.words_of(["abandon", "about"]), ["abandon", "about"])
        self.assertEqual(bip39.words_of(["abandon about"]), ["abandon", "about"])

    def test_an_empty_mnemonic_is_no_words(self):
        self.assertEqual(bip39.words_of(""), [])
        self.assertEqual(bip39.words_of([]), [])

    def test_a_non_string_word_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            bip39.words_of(["abandon", 7])  # type: ignore[list-item]

    def test_words_are_normalised(self):
        self.assertEqual(bip39.words_of(NFC_PASSPHRASE), [NFKD_PASSPHRASE])


# --- seeds ----------------------------------------------------------------


class SeedTest(unittest.TestCase):
    def test_every_published_vector_derives_its_seed(self):
        for entropy_hex, mnemonic, seed_hex in VECTORS:
            with self.subTest(entropy=entropy_hex):
                self.assertEqual(
                    bip39.mnemonic_to_seed(mnemonic, "TREZOR").hex(), seed_hex
                )

    def test_the_empty_passphrase_seed_is_the_one_the_node_answered(self):
        """Two implementations, one value: this module and astrald's."""
        self.assertEqual(bip39.mnemonic_to_seed(ZERO_MNEMONIC).hex(), LIVE_ZERO_SEED)

    def test_an_empty_passphrase_is_not_an_absent_salt(self):
        """The salt is `"mnemonic"` and then the passphrase, so an empty
        passphrase still salts."""
        self.assertNotEqual(
            bip39.mnemonic_to_seed(ZERO_MNEMONIC),
            hashlib.pbkdf2_hmac("sha512", ZERO_MNEMONIC.encode(), b"", 2048, 64),
        )

    def test_a_seed_is_sixty_four_bytes_at_every_mnemonic_length(self):
        for count in bip39.WORD_COUNTS:
            entropy = bip39.new_entropy(count * 11 - count // 3)
            words = bip39.entropy_to_mnemonic(entropy)
            with self.subTest(words=count):
                self.assertEqual(len(bip39.mnemonic_to_seed(words)), 64)

    def test_a_sequence_and_a_string_derive_one_seed(self):
        self.assertEqual(
            bip39.mnemonic_to_seed(ZERO_MNEMONIC.split()),
            bip39.mnemonic_to_seed(ZERO_MNEMONIC),
        )

    def test_the_mnemonic_is_validated_before_it_is_derived_from(self):
        """BIP-39 does not require it; astral-go does it and the node's op does
        it, so a local seed and a `bip137sig.seed` answer agree on which
        mnemonics exist."""
        with self.assertRaises(ParseError):
            bip39.mnemonic_to_seed(" ".join(["abandon"] * 12))

    def test_both_spellings_of_one_passphrase_derive_one_seed(self):
        """NFKD, which BIP-39 requires and astral-go omits. The node answered
        two different seeds for this pair, verified live."""
        self.assertEqual(
            bip39.mnemonic_to_seed(ZERO_MNEMONIC, NFC_PASSPHRASE).hex(), NFKD_SEED
        )
        self.assertEqual(
            bip39.mnemonic_to_seed(ZERO_MNEMONIC, NFKD_PASSPHRASE).hex(), NFKD_SEED
        )

    def test_the_unnormalised_seed_is_the_one_this_module_never_produces(self):
        """`UNNORMALISED_SEED` is what astrald answered for the NFC spelling. It
        is pinned so that a future implementation which drops the
        normalisation fails here rather than silently deriving somebody's wallet
        from a different seed."""
        self.assertNotEqual(bip39.mnemonic_to_seed(ZERO_MNEMONIC, NFC_PASSPHRASE).hex(),
                            UNNORMALISED_SEED)
        self.assertEqual(
            hashlib.pbkdf2_hmac(
                "sha512",
                ZERO_MNEMONIC.encode(),
                ("mnemonic" + NFC_PASSPHRASE).encode(),
                2048,
                64,
            ).hex(),
            UNNORMALISED_SEED,
        )

    def test_a_passphrase_changes_the_seed(self):
        self.assertNotEqual(
            bip39.mnemonic_to_seed(ZERO_MNEMONIC),
            bip39.mnemonic_to_seed(ZERO_MNEMONIC, "TREZOR"),
        )

    def test_a_non_string_passphrase_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            bip39.mnemonic_to_seed(ZERO_MNEMONIC, b"bytes")  # type: ignore[arg-type]


class NormalizeTest(unittest.TestCase):
    def test_nfkd_decomposes(self):
        self.assertEqual(bip39.normalize(NFC_PASSPHRASE), NFKD_PASSPHRASE)
        self.assertEqual(bip39.normalize(NFKD_PASSPHRASE), NFKD_PASSPHRASE)

    def test_nfkd_folds_compatibility_forms(self):
        """The K in NFKD: `ﬁ` is `fi`, which is why a passphrase typed in one
        editor and re-typed in another still derives one seed."""
        self.assertEqual(bip39.normalize("\ufb01"), "fi")

    def test_ascii_is_unchanged(self):
        self.assertEqual(bip39.normalize(ZERO_MNEMONIC), ZERO_MNEMONIC)

    def test_a_non_string_is_a_type_error(self):
        with self.assertRaises(BadArgumentType):
            bip39.normalize(7)  # type: ignore[arg-type]


class LiteralTest(unittest.TestCase):
    """The two spellings of one passphrase, before anything derives from them.

    Every normalisation claim in this file rests on the pair being two different
    strings. A tool that normalises the source makes them one, and each of those
    claims then passes while asserting nothing at all."""

    def test_the_two_spellings_are_different_strings(self):
        self.assertNotEqual(NFC_PASSPHRASE, NFKD_PASSPHRASE)
        self.assertEqual(len(NFC_PASSPHRASE), 1)
        self.assertEqual(len(NFKD_PASSPHRASE), 2)
        self.assertEqual(NFKD_PASSPHRASE.encode("utf-8"), b"e\xcc\x81")

    def test_they_are_one_value_after_normalisation(self):
        self.assertEqual(
            bip39.normalize(NFC_PASSPHRASE), bip39.normalize(NFKD_PASSPHRASE)
        )


class ErrorTaxonomyTest(unittest.TestCase):
    """Every fault out of this module is an `AstralError` and a `ValueError`."""

    def test_a_bad_size_is_both(self):
        with self.assertRaises(AstralError):
            bip39.new_entropy(7)
        with self.assertRaises(ValueError):
            bip39.new_entropy(7)

    def test_a_bad_mnemonic_is_both(self):
        with self.assertRaises(AstralError):
            bip39.mnemonic_to_entropy("nonsense")
        with self.assertRaises(ValueError):
            bip39.mnemonic_to_entropy("nonsense")

    def test_a_wrong_type_is_an_astral_error_and_a_type_error(self):
        with self.assertRaises(AstralError):
            bip39.normalize(7)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            bip39.normalize(7)  # type: ignore[arg-type]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
