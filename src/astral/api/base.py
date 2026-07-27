"""`ModuleClient`: the scaffolding every `astral.api.<module>` shares.

The per-op code is genuinely thin -- three to eight lines and a docstring -- so
op count is not what scales badly here. The per-*module* scaffolding is:
`__slots__`, `__init__`, `__repr__`, the `client` property, the `TYPES` sweep and
a private `_expect`. At two modules those were already two copies with **two
different message formats** for the same violation (`expected int, got 'object'`
against `expected 'int', got 'object'`), which is how thirteen modules end up
with thirteen dialects of the same fault. One base class, one message.

`_expect` is the only behaviour here, and it is worth centralising for a reason
beyond tidiness: an op that answered with a type it never declared is the
**remote** breaking its own contract, so it is a `ProtocolError` and not a
`TypeError`, and a caller wrapping a query in `except AstralError` has to see it.
Design section 4.7 makes op shape a per-op contract that is not discoverable from
the wire, so every method declares its own and this is where the declaration is
checked.

`Client` is imported at module scope and not under `TYPE_CHECKING`, so
`typing.get_type_hints` resolves every annotation in this package. The package
ships `py.typed`, which makes its annotations a supported interface, and an
interface that raises `NameError` on introspection is not one: `inspect.signature
(eval_str=True)`, doc generators and DI containers all read them at runtime.

The import is safe in that direction and only that direction. `client.py` imports
`astral.api.*` **inside** its property bodies, never at module scope, and
`astral/__init__.py` imports `astral.api` on its last line, after `astral.client`
is fully built. The arrow runs module clients -> client, and adding a
module-scope import the other way is what would close the cycle.
"""

from __future__ import annotations

from typing import Any, Sequence

from ..client import Client
from ..errors import ProtocolError

__all__ = ["ModuleClient"]


class ModuleClient:
    """One node module's ops, bound to one `Client`.

    Every method of every subclass takes the query keywords `Client.query` takes
    -- `target`, `caller`, `zone`, `filters`, `timeout`, `persistent`, `raw`,
    `fmt_in`, `fmt_out`, `nonce`, `allow_unparsed`, `context` -- and passes them
    through unread. A misspelled one therefore fails in `query()` rather than
    being dropped, which is the defect astral-go ships in its own clients: its
    `apphost.new_app_contract` sends `ID` and `Duration` capitalised, the node's
    parameter matching is case-sensitive, and unknown keys are silently
    discarded, so both arguments have never once reached the node (bug G-9).
    """

    __slots__ = ("_c",)

    TYPES: Sequence[type] = ()
    """Every wire type this module declares or re-exports.

    For a caller building a private `Blueprints` rather than the default one:
    `registry.add(*Dir.TYPES)`. Registration into the default registry has
    already happened at import (`astral/api/__init__.py`); this is the list, not
    the act.
    """

    def __init__(self, client: Client) -> None:
        self._c = client

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._c!r})"

    @property
    def client(self) -> Client:
        """The client every op on this module goes through."""
        return self._c

    def _one_shot(self, qs: str, kw: dict[str, Any]) -> Any:
        """One stream and one budget spanning the route **and** the answer.

        `call`, `call_one`, `call_raw` and `call_with` cover the ordinary shapes.
        An op whose reader is none of those -- `apphost.cancel` reads one object
        through `raw_objects()`, because its `error_message` is the answer rather
        than a failure -- still has to bound its body, or an accepted-and-silent
        responder holds one of the node's 32 workers for as long as the process
        lives.

        The delegation exists so that reaching into `Client` happens **once**
        rather than in each of thirteen modules. `_one_shot` is `Client`'s own
        private primitive and the budget object it yields is private too; module
        clients are part of this distribution and may use it, callers are not and
        may not.
        """
        return self._c._one_shot(qs, kw)  # noqa: SLF001 -- see the docstring

    @staticmethod
    def _expect(obj: Any, kind: type, op: str) -> Any:
        """The answer an op declared, or the fault of it having answered otherwise.

        One format for all thirteen modules: `op: expected <declared>, got
        <received>`, both names in the wire vocabulary where there is one, so the
        message reads in the same terms the docs and the node do.
        """
        if not isinstance(obj, kind):
            raise ProtocolError(
                f"{op}: expected {_name(kind)!r}, got {_name(type(obj))!r}"
            )
        return obj


def _name(kind: type) -> str:
    """A type's wire name, or its Python name when it has none."""
    return getattr(kind, "ASTRAL_TYPE", None) or kind.__name__
