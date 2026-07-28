"""`python -m astral` -- the `astral-query` command, without installing it.

Design section 6 names both entry points: the console script `astral-query`
declared in `pyproject.toml`, and this module. Both are the same `cli.main`, so
there is one argument parser, one exit-code table and one output format.

The module exists because the console script needs the distribution installed
and this needs only the package on `sys.path`, which is what a checkout has.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
