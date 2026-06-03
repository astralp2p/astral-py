"""Serve inbound queries for our own identity.

Registers a handler that answers any query with a greeting and ends the stream.
Requires an authenticated session (a token), since handlers may only be
registered for an identity the guest owns.

    ASTRALD_TOKEN=... python examples/serve.py
"""

import os
import sys
import time

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import astral


def handle(query: astral.IncomingQuery) -> None:
    print(f"inbound query {query.query!r} from {query.caller}")

    # Reject anything under the "admin" namespace with a custom code.
    if query.op.startswith("admin"):
        query.reject(3)
        return

    # Accept: the returned stream is the responder side of the query.
    stream = query.accept()
    try:
        stream.send(astral.obj("string8", f"hello {query.caller or 'anonymous'}"))
        stream.send_eos()
    finally:
        stream.close()


def main() -> None:
    with astral.connect() as node:
        if not node.guest_id:
            raise SystemExit("a token is required to serve (set ASTRALD_TOKEN)")

        registration = node.serve(handle)
        print(f"serving queries for {node.guest_id}; Ctrl-C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            registration.unregister()


if __name__ == "__main__":
    main()
