"""Tests for the non-terminating follow-drain path on :class:`~astral.stream.Stream`.

Follow-mode ops (``tree.get`` with ``follow``, ``services.discover`` with
``follow`` — see ``protocols/tree/ops/tree.get.md`` and
``protocols/services/ops/services.discover.md``) send an initial snapshot,
then a single ``eos`` that acts as a snapshot/live *separator* (not a
terminator), and then keep streaming live updates on the same channel until it
closes.

These tests drive a mock binary apphost node (the ``MockNode`` idiom from
``tests/test_integration_binary.py``) that streams snapshot objects, then
``eos``, then live objects, then closes the channel. They assert that

* :meth:`Stream.follow` yields BOTH the snapshot and the live objects across
  the separator, terminating on channel close; and
* the DEFAULT :meth:`Stream.__iter__` / :meth:`Stream.collect` still stop at the
  first ``eos`` (the follow path is purely additive and changes nothing).

The op name (``mock.follow``) is a generic stand-in: this PR is the Stream
enabler only, so no ``api/`` protocol helper is wired up.
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
from astral.objects import AstralObject, eos
from astral.transport.binary import BinaryChannel

HOST_ID = "02" + "ab" * 32
GUEST_ID = "03" + "cd" * 32

# The snapshot then the live tail streamed by the follow ops below.
SNAPSHOT = ["snap-a", "snap-b"]
LIVE = ["live-1", "live-2", "live-3"]


class MockNode:
    """A minimal binary apphost server that serves the follow-mode ops."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    @property
    def endpoint(self):
        return f"tcp:127.0.0.1:{self.port}"

    def start(self):
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept_loop(self):
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
            if first is None:
                return
            if isinstance(first, RouteQueryMsg):
                self._handle_query(ch, first)
            else:
                ch.send(ErrorMsg(Code="protocol_error"))
        except Exception:
            pass
        finally:
            ch.close()

    def _handle_query(self, ch, rq):
        op = rq.Query.split("?", 1)[0]
        ch.send(QueryAcceptedMsg())
        if op == "mock.follow":
            # snapshot, then the separator eos, then live updates, then close
            for value in SNAPSHOT:
                ch.send(AstralObject("string8", value))
            ch.send(eos())  # snapshot/live separator, NOT a terminator
            for value in LIVE:
                ch.send(AstralObject("string8", value))
            # channel close (from _handle's finally) ends the follow stream
        elif op == "mock.follow_eos":
            # a follow stream that closes with a trailing eos after the live tail
            for value in SNAPSHOT:
                ch.send(AstralObject("string8", value))
            ch.send(eos())  # separator
            for value in LIVE:
                ch.send(AstralObject("string8", value))
            ch.send(eos())  # trailing eos before close (must be swallowed too)
        elif op == "mock.follow_fail":
            # an error_message arriving in the live tail must raise
            for value in SNAPSHOT:
                ch.send(AstralObject("string8", value))
            ch.send(eos())  # separator
            ch.send(AstralObject("string8", LIVE[0]))
            ch.send(AstralObject("error_message", "it broke"))
            ch.send(eos())
        else:
            ch.send(eos())


class StreamFollowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = MockNode()
        cls.node.start()

    @classmethod
    def tearDownClass(cls):
        cls.node.stop()

    def connect(self):
        return astral.connect(self.node.endpoint)

    # -- follow-drain path --------------------------------------------------
    def test_follow_yields_snapshot_and_live_across_separator(self):
        with self.connect() as node:
            with node.query("mock.follow") as stream:
                values = [obj.value for obj in stream.follow()]
        self.assertEqual(values, SNAPSHOT + LIVE)

    def test_follow_swallows_trailing_eos_and_ends_on_close(self):
        with self.connect() as node:
            with node.query("mock.follow_eos") as stream:
                values = [obj.value for obj in stream.follow()]
        # both the separator eos and the trailing eos are swallowed; only the
        # objects come through, and the stream ends on channel close
        self.assertEqual(values, SNAPSHOT + LIVE)

    def test_follow_raises_on_error_message_in_live_tail(self):
        with self.connect() as node:
            with node.query("mock.follow_fail") as stream:
                gen = stream.follow()
                collected = []
                with self.assertRaises(astral.RemoteError):
                    for obj in gen:
                        collected.append(obj.value)
        # the snapshot and the pre-error live object arrive before the raise
        self.assertEqual(collected, SNAPSHOT + [LIVE[0]])

    def test_follow_caller_may_break_early(self):
        with self.connect() as node:
            with node.query("mock.follow") as stream:
                seen = []
                for obj in stream.follow():
                    seen.append(obj.value)
                    if len(seen) == len(SNAPSHOT):
                        break  # stop after the snapshot; caller controls the loop
        self.assertEqual(seen, SNAPSHOT)

    def test_follow_after_default_iter_reads_live_tail(self):
        # A caller that drains the snapshot with the default iterator first
        # (which stops at the first eos and marks _ended) can then call follow()
        # for the live tail: recv past the first eos works.
        with self.connect() as node:
            with node.query("mock.follow") as stream:
                snapshot = [obj.value for obj in stream]
                live = [obj.value for obj in stream.follow()]
        self.assertEqual(snapshot, SNAPSHOT)
        self.assertEqual(live, LIVE)

    # -- default path is UNCHANGED -----------------------------------------
    def test_default_iter_stops_at_first_eos(self):
        with self.connect() as node:
            with node.query("mock.follow") as stream:
                values = [obj.value for obj in stream]
        # the default iterator stops at the separator eos: snapshot only
        self.assertEqual(values, SNAPSHOT)

    def test_default_collect_stops_at_first_eos(self):
        with self.connect() as node:
            objs = node.call("mock.follow")
        self.assertEqual([o.value for o in objs], SNAPSHOT)

    def test_default_iter_sets_ended_at_first_eos(self):
        with self.connect() as node:
            with node.query("mock.follow") as stream:
                list(stream)  # drain to the first eos
                self.assertTrue(stream._ended)
                # recv() past the first eos returns None through the _ended gate
                self.assertIsNone(stream.recv())


if __name__ == "__main__":
    unittest.main()
