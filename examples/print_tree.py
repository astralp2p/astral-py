#!/usr/bin/env python3
"""Print the local node's configuration tree.

Walks the ``tree`` protocol (``protocols/tree``) starting from a root path,
using ``tree.list`` to discover child keys and ``tree.get`` to read leaf
values, and renders it like the unix ``tree`` command.

Usage::

    python examples/print_tree.py
    python examples/print_tree.py --path /mod/tcp
    python examples/print_tree.py --endpoint ws://127.0.0.1:8624/.ws --depth 3
    ASTRALD_TOKEN=... python examples/print_tree.py --no-values

Works over any transport (it only uses scalar result types).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import astral

# Box-drawing pieces for the tree view.
TEE = "├── "
ELBOW = "└── "
PIPE = "│   "
SPACE = "    "

_MAX_VALUE_LEN = 70


def join(base: str, name: str) -> str:
    """Join a tree path with a child key name."""
    return base + name if base.endswith("/") else base + "/" + name


def safe_list(node: astral.Client, path: str) -> list:
    """Child key names at ``path``; empty list if it is a leaf or errors."""
    try:
        return node.tree.list(path)
    except astral.AstralError:
        return []


def get_value(node: astral.Client, path: str):
    """Return the typed object stored at ``path``, or ``None`` if there is none."""
    try:
        return node.tree.get_object(path)
    except astral.AstralError:
        return None
    except KeyError:
        return None


def format_value(obj: astral.AstralObject) -> str:
    """Render a leaf value compactly, with its type."""
    value = obj.value
    type_name = obj.type or "untyped"
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            shown = repr(raw.decode("utf-8"))
        except UnicodeDecodeError:
            shown = f"0x{raw.hex()}" if raw else "<empty>"
    elif isinstance(value, (dict, list)):
        shown = json.dumps(value, separators=(",", ":"))
    else:
        shown = repr(value)
    if len(shown) > _MAX_VALUE_LEN:
        shown = shown[: _MAX_VALUE_LEN - 1] + "…"
    return f"{shown} \033[2m[{type_name}]\033[0m"


class TreeWalker:
    def __init__(self, node: astral.Client, *, show_values: bool, max_depth: int):
        self.node = node
        self.show_values = show_values
        self.max_depth = max_depth
        self.nodes = 0
        self.values = 0

    def walk(self, path: str, name: str, prefix: str, last: bool, depth: int) -> None:
        self.nodes += 1
        children = safe_list(self.node, path)

        label = name + ("/" if children else "")
        value_obj = get_value(self.node, path) if self.show_values else None
        if value_obj is not None:
            self.values += 1
            label = f"{label} = {format_value(value_obj)}"

        connector = ELBOW if last else TEE
        print(prefix + connector + label)

        if not children:
            return
        extension = SPACE if last else PIPE
        if depth >= self.max_depth:
            print(prefix + extension + ELBOW + "\033[2m… (depth limit)\033[0m")
            return

        for index, child in enumerate(children):
            self.walk(
                join(path, child),
                child,
                prefix + extension,
                index == len(children) - 1,
                depth + 1,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Print the local node's config tree")
    parser.add_argument("--endpoint", help="connection endpoint (default: local node)")
    parser.add_argument("--token", help="auth token (default: $ASTRALD_TOKEN)")
    parser.add_argument("--path", default="/", help="root path to print (default: /)")
    parser.add_argument(
        "--depth", type=int, default=64, help="maximum depth to descend (default: 64)"
    )
    parser.add_argument(
        "--no-values", action="store_true", help="show structure only, skip tree.get"
    )
    args = parser.parse_args()

    try:
        node = astral.connect(args.endpoint, token=args.token)
    except astral.AstralError as exc:
        print(f"could not connect to the node: {exc}", file=sys.stderr)
        print(
            "hint: pass --endpoint (e.g. ws://127.0.0.1:8624/.ws) and/or a token",
            file=sys.stderr,
        )
        return 1

    with node:
        alias = node.alias or "?"
        print(f"localnode tree  \033[2m(host: {alias} / {node.identity[:16]}…)\033[0m")
        root = args.path.rstrip("/") or "/"
        print(root)

        walker = TreeWalker(node, show_values=not args.no_values, max_depth=args.depth)
        children = safe_list(node, root)
        for index, child in enumerate(children):
            walker.walk(
                join(root, child),
                child,
                "",
                index == len(children) - 1,
                1,
            )

        if not children:
            print("\033[2m(empty)\033[0m")

        summary = f"\n{walker.nodes} node(s)"
        if not args.no_values:
            summary += f", {walker.values} value(s)"
        print(summary + f" under {root}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
