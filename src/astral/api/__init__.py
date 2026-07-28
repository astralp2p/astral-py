"""The module clients, and the guarantee that every wire type is registered.

One module per node module, each a thin class over `Client` whose methods are
the node's ops (design section 5.1). Nothing here opens a connection, holds
state or duplicates a transport path: an op is argument marshalling plus one
call to `Client.call`, `call_one`, `call_raw` or `stream`.

**Importing `astral.api` registers every type this SDK can decode.** That is why
the imports below are eager and unconditional, and why nothing in this package
is reached through a lazy `__getattr__`. Wire-type registration is a side effect
of importing a module, so leaving it to first attribute access makes decodability
depend on which property a caller happened to touch: `objects.find` returning a
`mod.dir.alias_map` would decode in a program that had used `client.dir` and
raise `BlueprintNotFound` in one that had not. That was a real latent bug in the
legacy SDK, and it is the kind that only ever shows up in production.

So: **every module added under `astral.api` gets a line here.** The rule is
enforced by a test rather than by discipline -- `tests/test_api_apphost.py`
imports this package and asserts that every module file in the directory is in
`sys.modules` afterwards, so a new module that forgets this file fails the suite
instead of failing a decode later. `astral/__init__.py` imports this package in
turn, so `import astral` is enough and no caller has to know the rule exists.

**And every module gets a `Client` property too**, in `client.py`, named after
the node module. That is the surface design sections 4.1 and 5.1 specify --
`client.dir`, `client.objects` -- and it is what makes the module client
reachable without the caller constructing one. The rule is enforced the same way
the import rule is, and for the same reason it had to be: this paragraph used to
claim a test walked every module and none did, so five modules landed with no
property at all while the suite stayed green and each of the five wrote the
omission into its own docstring as settled behaviour. A claim of enforcement
that is not enforced is worse than no claim, because it stops the next reader
looking. `tests/test_client.py::ModuleClientAttachmentTest` now globs this
directory and asserts every module carries a `functools.cached_property` of its
own name on `Client` and that the property caches.

Module *clients* are built lazily by that property and cached; that is a
construction detail with no bearing on registration. Registration is eager,
construction is not -- the two must not be confused, because a lazily *imported*
module client would make `client.call_one("dir.alias_map")` raise
`BlueprintNotFound` in any program that never touched `client.dir`.

Each module client inherits `base.ModuleClient`, which carries the scaffolding
(`__slots__`, `__init__`, `__repr__`, `client`, `TYPES`, `_expect`) so thirteen
modules do not grow thirteen dialects of the same shape-violation message.
"""

from __future__ import annotations

from . import apphost
from . import auth
from . import base
from . import crypto
from . import dir  # noqa: A004 -- the node module is named `dir`; so is this one
from . import objects
from . import services
from . import tree
from .apphost import Apphost
from .auth import Auth
from .base import ModuleClient
from .crypto import Crypto
from .dir import Dir
from .objects import Objects
from .services import Services
from .tree import Tree

# `dir` shadows the builtin for anyone who star-imports this package. It is named
# here anyway: the submodule takes the node module's name, and omitting it from
# `__all__` would only hide it from the reader, not from the import.
__all__ = [
    "Apphost",
    "Auth",
    "Crypto",
    "Dir",
    "ModuleClient",
    "Objects",
    "Services",
    "Tree",
    "apphost",
    "auth",
    "base",
    "crypto",
    "dir",
    "objects",
    "services",
    "tree",
]
