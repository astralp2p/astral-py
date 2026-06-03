"""End-to-end tests over a mock HTTP apphost listener.

Exercises the HTTP transport: bearer-token auth, the query string as the request
path, the ``X-Astral-*`` headers, JSON-lines responses and raw-byte bodies.
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import astral

HOST_ID = "02" + "ab" * 32
GUEST_ID = "03" + "cd" * 32
TOKEN = "httptoken"


def _make_handler():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence test output
            pass

        def _guest(self):
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {TOKEN}":
                return GUEST_ID
            return ""

        def do_GET(self):
            op = self.path.lstrip("/").split("?", 1)[0]
            if op == "objects.read":
                body = b"hello world"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self._common_headers()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            lines = []
            if op in ("apphost.whoami", "dir.resolve"):
                lines = [{"Type": "identity", "Object": HOST_ID}]
            elif op == "ping":
                lines = [{"Type": "string8", "Object": "pong"}, {"Type": "eos", "Object": None}]
            elif op == "tree.list":
                lines = [
                    {"Type": "string8", "Object": "tcp"},
                    {"Type": "string8", "Object": "tor"},
                    {"Type": "eos", "Object": None},
                ]
            elif op == "fail":
                lines = [{"Type": "error_message", "Object": "it broke"}]
            else:
                lines = [{"Type": "eos", "Object": None}]

            payload = ("\n".join(json.dumps(line) for line in lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._common_headers()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _common_headers(self):
            self.send_header("X-Astral-Host-Identity", HOST_ID)
            self.send_header("X-Astral-Guest-Identity", self._guest())

    return Handler


class HttpIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler())
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def connect(self, token=None):
        return astral.connect(self.url, token=token)

    def test_connect_captures_host_identity(self):
        with self.connect() as node:
            self.assertEqual(node.identity, HOST_ID)
            self.assertEqual(node.guest_id, "")

    def test_auth_via_bearer(self):
        with self.connect(token=TOKEN) as node:
            self.assertEqual(node.guest_id, GUEST_ID)

    def test_query_value(self):
        with self.connect() as node:
            self.assertEqual(node.call_one("ping"), "pong")
            self.assertEqual(node.dir.resolve("alice"), HOST_ID)

    def test_query_collect(self):
        with self.connect() as node:
            self.assertEqual(node.tree.list("/mod"), ["tcp", "tor"])

    def test_error_message_raises(self):
        with self.connect() as node:
            with self.assertRaises(astral.RemoteError):
                node.call_one("fail")

    def test_raw_read(self):
        with self.connect() as node:
            self.assertEqual(node.objects.read("data1abc"), b"hello world")

    def test_serving_not_supported(self):
        with self.connect(token=TOKEN) as node:
            self.assertFalse(node.supports_serving)
            with self.assertRaises(astral.NotSupported):
                node.register(GUEST_ID, lambda q: None)


if __name__ == "__main__":
    unittest.main()
