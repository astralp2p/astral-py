"""Connect to the local node and run a few read-only queries.

Run with the node's apphost endpoint reachable, e.g.::

    ASTRALD_TOKEN=... python examples/basics.py
    python examples/basics.py ws://127.0.0.1:8624/.ws
"""

import os
import sys

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import astral


def main() -> None:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else None

    with astral.connect(endpoint) as node:
        print(f"host identity : {node.identity}")
        print(f"host alias    : {node.alias}")
        print(f"guest id      : {node.guest_id or '(anonymous)'}")

        # apphost.whoami — the identity the host sees us as.
        print(f"whoami        : {node.whoami()}")

        # The tree protocol is a config key/value store.
        try:
            children = node.tree.list("/mod")
            print(f"/mod children : {', '.join(children)}")
        except astral.AstralError as exc:
            print(f"tree.list failed: {exc}")

        # Resolve an alias to an identity (if one exists).
        if len(sys.argv) > 2:
            name = sys.argv[2]
            print(f"resolve {name!r} : {node.dir.resolve(name)}")


if __name__ == "__main__":
    main()
