"""Compute and parse Astral Object IDs (no node connection required).

    python examples/object_ids.py
"""

import os
import sys

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import astral


def main() -> None:
    # An untyped object: the id is over the raw payload.
    oid = astral.compute_object_id(b"hello world")
    print(f"payload     : 'hello world'")
    print(f"size        : {oid.size}")
    print(f"object id   : {oid}")

    # Round-trips through the zBase32 "data1..." string form.
    parsed = astral.ObjectID.parse(str(oid))
    assert parsed == oid
    print(f"reparsed    : {parsed} (size={parsed.size})")

    # A typed object's encoding includes the Stamp + type header.
    typed = astral.compute_object_id(b"\x15", "uint8")
    print(f"typed uint8 : {typed}")


if __name__ == "__main__":
    main()
