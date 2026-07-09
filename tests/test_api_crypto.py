"""End-to-end tests for the ``crypto`` protocol helper over a mock binary node.

Exercises the two hash ops added here — ``sign_hash`` and
``verify_hash_signature`` — plus their text counterparts (``sign_text`` /
``verify_text_signature``) to pin that the hash ops mirror the text ops' style:
op strings, query-arg wiring (``key``/``scheme`` sent only when provided), the
``<scheme>:<sig>`` string result, and the non-error/ack => True verify heuristic
(and its error behaviour). All crypto ops are opaque-string, query-arg only and
untested against a live node (see ``api/crypto.py``); these tests pin the wiring
against a mock, not real crypto.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.messages import (
    AuthSuccessMsg,
    AuthTokenMsg,
    ErrorMsg,
    HostInfoMsg,
    QueryAcceptedMsg,
    RouteQueryMsg,
)
from astral.objects import AstralObject, ack, eos
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
# Opaque scheme:hex/b64 tokens — the SDK passes them straight through as strings.
HASH_HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
KEY = "secp256k1:02bef8840eb35ef2ae3c83c07cb5779278904f99cb4103f71e37cc69931ae5e15f"
HASH_SIG = "asn1:MEUCIQDg+5AiB7H1k="
TEXT_SIG = "bip137:H3p1c1AY2W2NwO="


class CryptoMockNode:
    """A minimal binary apphost server tailored to the crypto ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.seen = []  # every query string received

    @property
    def endpoint(self):
        return f"tcp:127.0.0.1:{self.port}"

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        ch = BinaryChannel(conn)
        try:
            ch.send(HostInfoMsg(Identity=HOST_ID, Alias="mock"))
            first = ch.recv()
            if isinstance(first, AuthTokenMsg):
                ch.send(AuthSuccessMsg(GuestID=HOST_ID))
                first = ch.recv()
            if isinstance(first, RouteQueryMsg):
                self._query(ch, first)
            else:
                ch.send(ErrorMsg(Code="protocol_error"))
        except Exception:
            pass
        finally:
            ch.close()

    def _query(self, ch, rq):
        op = rq.Query.split("?", 1)[0]
        self.seen.append(rq.Query)
        ch.send(QueryAcceptedMsg())

        if op == "crypto.sign_hash":
            # A node emits the signature in its `<scheme>:<base64>` text form; on
            # the text/JSON transports (and here, as the scalar `string8` mock of
            # it) that reads back as a plain Python str. The opaque token is
            # passed straight through — no record decode (see api/crypto.py).
            ch.send(AstralObject("string8", HASH_SIG))
            ch.send(eos())
        elif op == "crypto.sign_text":
            ch.send(AstralObject("string8", TEXT_SIG))
            ch.send(eos())
        elif op in ("crypto.verify_hash_signature", "crypto.verify_text_signature"):
            # A bad-key query fails verification; anything else acks (valid).
            if "key=bad" in rq.Query:
                ch.send(AstralObject("error_message", "verification failed"))
            else:
                ch.send(ack())
            ch.send(eos())
        else:
            ch.send(eos())


class CryptoBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = CryptoMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        # `seen` accumulates across the shared node; reset it so each test's
        # arg-wiring assertions see only its own queries.
        self.node.seen = []

    def connect(self):
        return astral.connect(self.node.endpoint)

    # -- sign_hash ----------------------------------------------------------
    def test_sign_hash_returns_signature_string(self):
        with self.connect() as c:
            sig = c.crypto.sign_hash(HASH_HEX)
        self.assertIsInstance(sig, str)
        self.assertEqual(sig, HASH_SIG)
        # bare op: no key/scheme sent when the caller omits them
        self.assertIn("crypto.sign_hash?hash=" + HASH_HEX, self.node.seen)

    def test_sign_hash_omits_scheme_by_default(self):
        # The node defaults sign_hash's scheme to asn1; the SDK must NOT hardcode
        # a scheme, so a bare call sends exactly `hash=` — no scheme, no key.
        with self.connect() as c:
            c.crypto.sign_hash(HASH_HEX)
        self.assertIn("crypto.sign_hash?hash=" + HASH_HEX, self.node.seen)
        self.assertFalse(
            self._seen(
                lambda s: s.startswith("crypto.sign_hash?")
                and ("scheme=" in s or "key=" in s)
            )
        )

    def test_sign_hash_wires_key_and_scheme_when_given(self):
        with self.connect() as c:
            c.crypto.sign_hash(HASH_HEX, key=KEY, scheme="asn1")
        self.assertTrue(
            self._seen(
                lambda s: s.startswith("crypto.sign_hash?")
                and "hash=" + HASH_HEX in s
                and "scheme=asn1" in s
                and "key=secp256k1" in s
            )
        )

    # -- verify_hash_signature ---------------------------------------------
    def test_verify_hash_signature_true_on_ack(self):
        with self.connect() as c:
            ok = c.crypto.verify_hash_signature(HASH_HEX, HASH_SIG, KEY)
        self.assertIs(ok, True)

    def test_verify_hash_signature_wires_hash_sig_key(self):
        with self.connect() as c:
            c.crypto.verify_hash_signature(HASH_HEX, HASH_SIG, KEY)
        self.assertTrue(
            self._seen(
                lambda s: s.startswith("crypto.verify_hash_signature?")
                and "hash=" + HASH_HEX in s
                and "sig=asn1" in s
                and "key=secp256k1" in s
            )
        )

    def test_verify_hash_signature_error_raises(self):
        # Mirrors verify_text_signature: an error_message surfaces as RemoteError.
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.crypto.verify_hash_signature(HASH_HEX, HASH_SIG, "bad")

    # -- parity with the text ops ------------------------------------------
    def test_hash_ops_match_text_ops_behaviour(self):
        with self.connect() as c:
            text_sig = c.crypto.sign_text("hello world")
            hash_sig = c.crypto.sign_hash(HASH_HEX)
            self.assertIsInstance(text_sig, str)
            self.assertIsInstance(hash_sig, str)
            self.assertIs(c.crypto.verify_text_signature("hello world", TEXT_SIG, KEY), True)
            self.assertIs(c.crypto.verify_hash_signature(HASH_HEX, HASH_SIG, KEY), True)
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.crypto.verify_text_signature("hello world", TEXT_SIG, "bad")
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.crypto.verify_hash_signature(HASH_HEX, HASH_SIG, "bad")

    def _seen(self, predicate):
        return any(predicate(s) for s in self.node.seen)


if __name__ == "__main__":
    unittest.main()
