"""End-to-end tests for the ``crypto`` protocol helper over a mock binary node.

Pins the two input styles against the astrald ops (``mod/crypto/src/op_*.go``):

* ``sign_text`` / ``sign_hash`` — query-arg driven; the ``<scheme>:<sig>`` string
  result and the ``key``/``scheme``-only-when-given wiring.
* ``verify_*`` / ``public_key`` — STREAMED input on the channel body. The
  signature (verify) / private key (public_key) is sent as an object, NOT a query
  arg. Regression pins: verify returns ``True`` only on an ``ack``, ``False`` on an
  error and — critically — ``False`` when the node sends no ack (the old query-arg
  form returned ``True`` on the empty stream), and the signature is absent from the
  query string.

Plus record round-trips for the net-new ``mod.crypto.public_key`` (hex text) and
``mod.crypto.private_key`` (base64 text). Mock wiring, not real crypto.
"""

import base64
import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.crypto import PrivateKey, PublicKey, Signature
from astral.codec import BinaryReader, BinaryWriter
from astral.messages import (
    AuthSuccessMsg,
    AuthTokenMsg,
    ErrorMsg,
    HostInfoMsg,
    QueryAcceptedMsg,
    RouteQueryMsg,
)
from astral.objects import AstralObject, ack, eos
from astral.registry import record_for
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
HASH_HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
# A compressed secp256k1 public key (33 bytes) -> "<type>:<hex>" text == KEY.
PUB_HEX = "02bef8840eb35ef2ae3c83c07cb5779278904f99cb4103f71e37cc69931ae5e15f"
PUB_BYTES = bytes.fromhex(PUB_HEX)
KEY = "secp256k1:" + PUB_HEX
PRIV = "secp256k1:" + base64.b64encode(bytes(range(32))).decode()

# Valid "<scheme>:<base64>" signature tokens (Signature.from_value base64-decodes).
HASH_SIG = "asn1:" + base64.b64encode(b"a-hash-signature").decode()
TEXT_SIG = "bip137:" + base64.b64encode(b"a-text-signature").decode()
BAD_SIG = "bad:" + base64.b64encode(b"nope").decode()        # mock -> error_message
SILENT_SIG = "silent:" + base64.b64encode(b"none").decode()  # mock -> no ack, only eos


# ======================================================================
# Record round-trips (the net-new public/private key records)
# ======================================================================
class KeyRecordTest(unittest.TestCase):
    def _roundtrip_binary(self, rec):
        w = BinaryWriter()
        rec.write_to(w)
        return type(rec).read_from(BinaryReader(w.getvalue()))

    def test_public_key_text_is_hex(self):
        pk = PublicKey(type="secp256k1", key=PUB_BYTES)
        self.assertEqual(pk.text, KEY)
        self.assertEqual(PublicKey.from_value(KEY), pk)

    def test_private_key_text_is_base64(self):
        pk = PrivateKey(type="secp256k1", key=bytes(range(32)))
        self.assertEqual(pk.text, PRIV)
        self.assertEqual(PrivateKey.from_value(PRIV), pk)

    def test_records_registered(self):
        self.assertIs(record_for("mod.crypto.public_key"), PublicKey)
        self.assertIs(record_for("mod.crypto.private_key"), PrivateKey)

    def test_binary_and_json_roundtrip(self):
        for rec in (PublicKey(type="secp256k1", key=PUB_BYTES),
                    PrivateKey(type="secp256k1", key=bytes(range(32)))):
            self.assertEqual(self._roundtrip_binary(rec), rec)
            self.assertEqual(type(rec).from_value(rec.encode_json()), rec)


# ======================================================================
# Ops over a mock binary node
# ======================================================================
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
            # The node replies with a mod.crypto.signature OBJECT (astrald
            # ch.Send(sig)); the client renders it to its <scheme>:<base64> text.
            ch.send(AstralObject("mod.crypto.signature",
                                 Signature(scheme="asn1", data=b"a-hash-signature")))
            ch.send(eos())
        elif op == "crypto.sign_text":
            ch.send(AstralObject("mod.crypto.signature",
                                 Signature(scheme="bip137", data=b"a-text-signature")))
            ch.send(eos())
        elif op in ("crypto.verify_hash_signature", "crypto.verify_text_signature"):
            # The signature is STREAMED, not a query arg: read it, then decide by
            # its scheme (mirrors astrald's ch.Switch(crypto.Signature) branch).
            sig = ch.recv()
            scheme = getattr(getattr(sig, "value", None), "scheme", None)
            if scheme == "bad":
                ch.send(AstralObject("error_message", "verification failed"))
                ch.send(eos())
            elif scheme == "silent":
                ch.send(eos())  # no ack: the node did not confirm -> verify is False
            else:
                ch.send(ack())
                ch.send(eos())
        elif op == "crypto.public_key":
            ch.recv()  # the streamed mod.crypto.private_key
            ch.send(AstralObject("mod.crypto.public_key",
                                 PublicKey(type="secp256k1", key=PUB_BYTES)))
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
        self.node.seen = []

    def connect(self):
        return astral.connect(self.node.endpoint)

    def _seen(self, predicate):
        return any(predicate(s) for s in self.node.seen)

    # -- sign (query-arg) ---------------------------------------------------
    def test_sign_hash_returns_signature_string(self):
        with self.connect() as c:
            sig = c.crypto.sign_hash(HASH_HEX)
        self.assertEqual(sig, HASH_SIG)
        self.assertIn("crypto.sign_hash?hash=" + HASH_HEX, self.node.seen)

    def test_sign_hash_omits_scheme_by_default(self):
        with self.connect() as c:
            c.crypto.sign_hash(HASH_HEX)
        self.assertFalse(self._seen(
            lambda s: s.startswith("crypto.sign_hash?") and ("scheme=" in s or "key=" in s)))

    def test_sign_text_wires_key_and_scheme_when_given(self):
        with self.connect() as c:
            c.crypto.sign_text("hello", key=KEY, scheme="bip137")
        self.assertTrue(self._seen(
            lambda s: s.startswith("crypto.sign_text?")
            and "scheme=bip137" in s and "key=secp256k1" in s))

    # -- verify (streamed signature) ---------------------------------------
    def test_verify_text_true_on_ack(self):
        with self.connect() as c:
            self.assertIs(c.crypto.verify_text_signature("hello", TEXT_SIG, KEY), True)

    def test_verify_hash_true_on_ack(self):
        with self.connect() as c:
            self.assertIs(c.crypto.verify_hash_signature(HASH_HEX, HASH_SIG, KEY), True)

    def test_verify_false_on_invalid_signature(self):
        # An error reply is a normal False, not an exception.
        with self.connect() as c:
            self.assertIs(c.crypto.verify_text_signature("hello", BAD_SIG, KEY), False)
            self.assertIs(c.crypto.verify_hash_signature(HASH_HEX, BAD_SIG, KEY), False)

    def test_verify_false_when_node_sends_no_ack(self):
        # Regression: the old query-arg form streamed no signature, so the node
        # never acked and the empty stream was read as True. It must be False.
        with self.connect() as c:
            self.assertIs(c.crypto.verify_text_signature("hello", SILENT_SIG, KEY), False)

    def test_verify_streams_signature_not_query_arg(self):
        with self.connect() as c:
            c.crypto.verify_text_signature("hello", TEXT_SIG, KEY)
        self.assertTrue(self._seen(lambda s: s.startswith("crypto.verify_text_signature?")))
        # the signature must NOT ride in the query string
        self.assertFalse(self._seen(lambda s: "sig=" in s or base64.b64encode(b"a-text-signature").decode() in s))

    def test_verify_key_optional(self):
        with self.connect() as c:
            self.assertIs(c.crypto.verify_text_signature("hello", TEXT_SIG), True)
        self.assertFalse(self._seen(
            lambda s: s.startswith("crypto.verify_text_signature?") and "key=" in s))

    # -- public_key (streamed private key) ---------------------------------
    def test_public_key_streams_private_and_returns_text(self):
        with self.connect() as c:
            pub = c.crypto.public_key(PRIV)
        self.assertEqual(pub, KEY)
        # no key/scheme query arg — the op takes only In/Out
        self.assertTrue(self._seen(lambda s: s.split("?", 1)[0] == "crypto.public_key"))
        self.assertFalse(self._seen(
            lambda s: s.startswith("crypto.public_key?") and ("key=" in s or "scheme=" in s)))

    def test_public_key_accepts_record(self):
        with self.connect() as c:
            pub = c.crypto.public_key(PrivateKey.from_value(PRIV))
        self.assertEqual(pub, KEY)


if __name__ == "__main__":
    unittest.main()
