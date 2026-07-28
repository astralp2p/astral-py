"""Which `astral.api` modules declare ops, walked rather than listed.

Two suites assert the same rule from two angles -- `test_api_apphost.py` checks
the type sweep and the client property, `test_client.py` checks that the
property is a caching one -- and both walk the package directory rather than a
hand-written list, because a hand-written list is what let five modules land
with no property at all while the suite stayed green.

The walk needs one refinement it did not need at seven modules: **a module that
declares no op has no module client and no `Client` property**. Design section
0.1 puts two such modules in this package on purpose -- excluding a module means
excluding its **ops**, not its **types**, and `mod.nodes.node_info` cannot decode
without `mod.tcp.endpoint` -- so `exonet` is an abstract base class and a
registry and `endpoints` is four wire types. A `client.exonet` would name a set
of ops that does not exist.

The refinement is a property of the module, not a name on a list: a module is an
ops module when it declares a `base.ModuleClient` subclass of its own. Adding
`api/nat.py` with ops therefore still fails both suites until `client.nat`
exists, which is the whole point of walking.
"""

from __future__ import annotations

import importlib
import pathlib


def module_names() -> list[str]:
    """Every module in `astral.api`, sorted. `base` and private names excluded."""
    import astral.api

    directory = pathlib.Path(astral.api.__file__).parent
    return sorted(
        path.stem
        for path in directory.glob("*.py")
        if not path.stem.startswith("_") and path.stem != "base"
    )


def declares_ops(name: str) -> bool:
    """Whether `astral.api.<name>` declares a module client of its own.

    Its own: a module that imports another module's client -- as `endpoints`
    imports nothing but wire types, and as any module may import a sibling --
    does not thereby acquire ops.
    """
    from astral.api.base import ModuleClient

    module = importlib.import_module(f"astral.api.{name}")
    return any(
        isinstance(value, type)
        and issubclass(value, ModuleClient)
        and value is not ModuleClient
        and value.__module__ == module.__name__
        for value in vars(module).values()
    )


def op_modules() -> list[str]:
    """Every module in `astral.api` that declares ops, sorted.

    The set both suites walk: each of these has a `TYPES` sweep, a
    `<NAME>_TYPES` tuple and a `functools.cached_property` on `Client`.
    """
    return [name for name in module_names() if declares_ops(name)]


def type_only_modules() -> list[str]:
    """Every module in `astral.api` that declares no op, sorted.

    Named so the count is asserted rather than assumed: a module that lost its
    client by accident would otherwise vanish from both walks in silence.
    """
    return [name for name in module_names() if not declares_ops(name)]
