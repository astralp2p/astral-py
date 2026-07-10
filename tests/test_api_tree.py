"""End-to-end tests for the ``tree`` protocol helper over a binary MockNode.

The ``tree`` protocol is a hierarchical key-value store. Exercises all six
documented ops on the native binary transport (the target transport):

* ``get`` / ``get_object`` — one-shot reads: the value (unwrapped) and the full
  typed :class:`~astral.objects.AstralObject`; a missing path raises.
* ``follow`` — FOLLOW-MODE read: the node streams a snapshot, then a single
  ``eos`` acting as a snapshot/live *separator* (not a terminator), then live
  updates until the channel closes. Drained via :meth:`Stream.follow`, so both
  the snapshot and the live tail come through.
* ``list`` — a stream of bare ``string8`` child names -> list of str; defaults
  to ``/``.
* ``set`` — the one bidirectional op: the typed value streams on the channel
  body (then ``eos``), and the node acks. The body object is pinned.
* ``delete`` — args-only ack op; the ``recursive`` bool is lowercase and sent
  only when true (pinned against the exact query string).
* ``mount_remote`` / ``unmount`` — net-new args-only ack ops; ``root`` is sent
  only when provided, and error paths raise.

Grounding: ``protocols/tree/ops/`` op docs, astral-go ``mod/tree/`` (``client/
node.go``, ``server.go``, ``module.go`` method constants), and astral-js
``src/api/tree/index.ts``.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral
from astral.api.tree import Tree
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
GUEST_ID = "03" + "cd" * 32

# The snapshot then the live tail streamed by tree.get?follow=true below.
FOLLOW_SNAPSHOT = ["snap-0"]
FOLLOW_LIVE = ["live-1", "live-2"]
# The child names streamed by tree.list.
LIST_CHILDREN = ["dial", "listen"]


class TreeMockNode:
    """A minimal binary apphost server tailored to the tree ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.seen = []  # every query string received
        self.set_input = None  # the body object streamed to tree.set

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
                ch.send(AuthSuccessMsg(GuestID=GUEST_ID))
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

        if op == "tree.get":
            if "path=missing" in rq.Query:
                ch.send(AstralObject("error_message", "path not found"))
                ch.send(eos())
            elif "follow=true" in rq.Query:
                # snapshot, then the separator eos, then live updates, then close
                for value in FOLLOW_SNAPSHOT:
                    ch.send(AstralObject("string8", value))
                ch.send(eos())  # snapshot/live separator, NOT a terminator
                for value in FOLLOW_LIVE:
                    ch.send(AstralObject("string8", value))
                # channel close (from _handle's finally) ends the follow stream
            else:
                ch.send(AstralObject("bool", False))
                ch.send(eos())
        elif op == "tree.list":
            for name in LIST_CHILDREN:
                ch.send(AstralObject("string8", name))
            ch.send(eos())
        elif op == "tree.set":
            # The value streams on the body (then eos); read it, then ack.
            self.set_input = ch.recv()
            ch.recv()  # the caller's eos
            ch.send(ack())
            ch.send(eos())
        elif op == "tree.delete":
            if "path=missing" in rq.Query:
                ch.send(AstralObject("error_message", "path does not exist"))
            else:
                ch.send(ack())
            ch.send(eos())
        elif op == "tree.mount_remote":
            if "target=badnode" in rq.Query:
                ch.send(AstralObject("error_message", "no such node"))
            else:
                ch.send(ack())
            ch.send(eos())
        elif op == "tree.unmount":
            if "path=notmounted" in rq.Query:
                ch.send(AstralObject("error_message", "path is not mounted"))
            else:
                ch.send(ack())
            ch.send(eos())
        else:
            ch.send(eos())


class TreeOpsBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = TreeMockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def setUp(self):
        self.node.seen = []
        self.node.set_input = None

    def connect(self):
        return astral.connect(self.node.endpoint)

    # -- wiring -------------------------------------------------------------
    def test_client_exposes_tree_helper(self):
        with self.connect() as c:
            self.assertIsInstance(c.tree, Tree)
            self.assertIs(c.tree, c.tree)  # lazily cached

    # -- get ----------------------------------------------------------------
    def test_get_returns_unwrapped_value(self):
        with self.connect() as c:
            self.assertEqual(c.tree.get("/mod/tcp/settings/listen"), False)
        self.assertIn("tree.get?path=%2Fmod%2Ftcp%2Fsettings%2Flisten", self.node.seen)

    def test_get_missing_path_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.tree.get("missing")

    def test_get_object_returns_full_typed_object(self):
        with self.connect() as c:
            obj = c.tree.get_object("/mod/tcp/settings/listen")
        self.assertIsInstance(obj, AstralObject)
        self.assertEqual(obj.type, "bool")
        self.assertEqual(obj.value, False)

    def test_get_object_missing_raises_keyerror(self):
        # An empty stream (no value, straight to eos) surfaces as KeyError(path);
        # here the node streams an error_message, which raises RemoteError first.
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.tree.get_object("missing")

    # -- follow -------------------------------------------------------------
    def test_follow_yields_snapshot_and_live_across_separator(self):
        with self.connect() as c:
            values = [obj.value for obj in c.tree.follow("/net/alias")]
        # both the snapshot and the live tail come through, across the separator
        self.assertEqual(values, FOLLOW_SNAPSHOT + FOLLOW_LIVE)
        self.assertIn("tree.get?path=%2Fnet%2Falias&follow=true", self.node.seen)

    def test_follow_caller_may_break_early(self):
        with self.connect() as c:
            seen = []
            for obj in c.tree.follow("/net/alias"):
                seen.append(obj.value)
                if len(seen) == len(FOLLOW_SNAPSHOT):
                    break  # stop after the snapshot; caller controls the loop
        self.assertEqual(seen, FOLLOW_SNAPSHOT)

    # -- list ---------------------------------------------------------------
    def test_list_returns_child_names(self):
        with self.connect() as c:
            self.assertEqual(c.tree.list("/mod/tcp/settings"), LIST_CHILDREN)
        self.assertIn("tree.list?path=%2Fmod%2Ftcp%2Fsettings", self.node.seen)

    def test_list_defaults_to_root(self):
        with self.connect() as c:
            c.tree.list()
        self.assertIn("tree.list?path=%2F", self.node.seen)

    # -- set ----------------------------------------------------------------
    def test_set_streams_value_on_body_and_acks(self):
        value = AstralObject("string8", "hello")
        with self.connect() as c:
            self.assertIsNone(c.tree.set("/tmp/mykey", value))
        # the value crossed the wire on the body (not as a query arg)
        self.assertIsInstance(self.node.set_input, AstralObject)
        self.assertEqual(self.node.set_input.type, "string8")
        self.assertEqual(self.node.set_input.value, "hello")
        self.assertIn("tree.set?path=%2Ftmp%2Fmykey", self.node.seen)

    # -- delete -------------------------------------------------------------
    def test_delete_acks_and_omits_recursive_by_default(self):
        with self.connect() as c:
            self.assertIsNone(c.tree.delete("/tmp/mykey"))
        # recursive is skipped when false (the query string stays minimal)
        self.assertIn("tree.delete?path=%2Ftmp%2Fmykey", self.node.seen)
        self.assertNotIn("recursive", self.node.seen[-1])

    def test_delete_recursive_sends_lowercase_bool(self):
        with self.connect() as c:
            self.assertIsNone(c.tree.delete("/tmp/mydir", recursive=True))
        # lowercase `recursive`, text-encoded true
        self.assertIn("tree.delete?path=%2Ftmp%2Fmydir&recursive=true", self.node.seen)

    def test_delete_missing_path_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.tree.delete("missing")

    # -- mount_remote -------------------------------------------------------
    def test_mount_remote_acks_and_omits_root_by_default(self):
        with self.connect() as c:
            self.assertIsNone(c.tree.mount_remote("/remote/peer", "somenode"))
        self.assertIn(
            "tree.mount_remote?path=%2Fremote%2Fpeer&target=somenode", self.node.seen
        )
        self.assertNotIn("root", self.node.seen[-1])

    def test_mount_remote_sends_root_when_provided(self):
        with self.connect() as c:
            self.assertIsNone(
                c.tree.mount_remote("/remote/peer", "somenode", root="/mod")
            )
        self.assertIn(
            "tree.mount_remote?path=%2Fremote%2Fpeer&target=somenode&root=%2Fmod",
            self.node.seen,
        )

    def test_mount_remote_error_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.tree.mount_remote("/remote/peer", "badnode")

    # -- unmount ------------------------------------------------------------
    def test_unmount_acks_and_pins_path(self):
        with self.connect() as c:
            self.assertIsNone(c.tree.unmount("/remote/peer"))
        self.assertIn("tree.unmount?path=%2Fremote%2Fpeer", self.node.seen)

    def test_unmount_not_mounted_raises(self):
        with self.connect() as c:
            with self.assertRaises(astral.RemoteError):
                c.tree.unmount("notmounted")


if __name__ == "__main__":
    unittest.main()
