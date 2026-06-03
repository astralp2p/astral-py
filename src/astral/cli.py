"""A small ``astral-query``-style command line.

Usage::

    python -m astral [options] [target:]<operation> [-<param> <value> ...]

Options:
    --endpoint URL   connection endpoint (default: local node)
    --token TOKEN    auth token (default: $ASTRALD_TOKEN)
    --target ID      target identity (alias or hex pubkey)
    --json           print results as JSON envelopes

Examples::

    python -m astral dir.resolve -name alice
    python -m astral tree.list -path /mod --json
    python -m astral --endpoint ws://127.0.0.1:8624/.ws apphost.whoami
"""

from __future__ import annotations

import json
import sys
from typing import List, Optional

from . import connect
from .encoding import to_json_envelope
from .errors import AstralError, EncodingError

_USAGE = "usage: python -m astral [options] [target:]<operation> [-<param> <value> ...]"


def _is_hex_identity(value: str) -> bool:
    """True if ``value`` looks like a 66-hex-digit identity public key."""
    if len(value) != 66:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _format(obj, as_json: bool) -> str:
    if as_json:
        try:
            return json.dumps(to_json_envelope(obj))
        except EncodingError:
            value = obj.value.hex() if isinstance(obj.value, (bytes, bytearray)) else obj.value
            return json.dumps({"Type": obj.type, "Object": value})
    value = obj.value
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    return f"{obj.type or '<untyped>'}\t{value}"


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    endpoint = token = target = None
    as_json = False
    op = None
    args: dict = {}

    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-h", "--help"):
            print(__doc__)
            return 0
        if tok == "--endpoint":
            endpoint, i = argv[i + 1], i + 2
        elif tok == "--token":
            token, i = argv[i + 1], i + 2
        elif tok == "--target":
            target, i = argv[i + 1], i + 2
        elif tok == "--json":
            as_json, i = True, i + 1
        elif op is None and not tok.startswith("-"):
            # operation, optionally "target:operation"
            if ":" in tok:
                prefix, op = tok.split(":", 1)
                target = target or prefix
            else:
                op = tok
            i += 1
        elif tok.startswith("-") and op is not None:
            if i + 1 >= len(argv):
                print(f"missing value for {tok}", file=sys.stderr)
                return 2
            args[tok.lstrip("-")], i = argv[i + 1], i + 2
        else:
            print(_USAGE, file=sys.stderr)
            return 2

    if op is None:
        print(_USAGE, file=sys.stderr)
        return 2

    try:
        node = connect(endpoint, token=token)
    except AstralError as exc:
        print(f"connect failed: {exc}", file=sys.stderr)
        return 1

    rc = 0
    try:
        # The apphost Target is an identity; resolve alias targets first.
        if target and not _is_hex_identity(target):
            target = node.dir.resolve(target)
        with node.query(op, args, target=target) as stream:
            if op.split("?", 1)[0] == "objects.read":
                sys.stdout.buffer.write(stream.read())
                return 0
            for obj in stream:
                if obj.is_error:
                    print(f"error: {obj.value}", file=sys.stderr)
                    rc = 1
                else:
                    print(_format(obj, as_json))
    except AstralError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        rc = 1
    finally:
        node.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
