"""Send a generic query and iterate the streamed result objects.

    python examples/query_stream.py tree.list -path /mod
    python examples/query_stream.py dir.resolve -name alice
"""

import os
import sys

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import astral


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: query_stream.py <operation> [-param value ...]")
        raise SystemExit(2)

    op = sys.argv[1]
    args = {}
    rest = sys.argv[2:]
    for i in range(0, len(rest) - 1, 2):
        args[rest[i].lstrip("-")] = rest[i + 1]

    with astral.connect() as node:
        with node.query(op, args) as stream:
            for obj in stream.results():  # raises on error_message, stops at eos
                print(f"{obj.type}: {obj.value!r}")


if __name__ == "__main__":
    main()
