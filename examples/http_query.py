"""Use the HTTP transport for a simple request/response query.

The HTTP transport (default ``http://localhost:8624``) is the simplest path for
one-shot queries; it cannot stream input or serve inbound queries.

    ASTRALD_TOKEN=... python examples/http_query.py
"""

import os
import sys

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import astral


def main() -> None:
    with astral.connect("http://localhost:8624") as node:
        print(f"host : {node.identity}")
        print(f"me   : {node.whoami()}")

        # Every result object arrives as a JSON envelope, decoded to a value.
        for obj in node.call("tree.list", {"path": "/mod"}):
            print(f"  /mod/{obj.value}")


if __name__ == "__main__":
    main()
