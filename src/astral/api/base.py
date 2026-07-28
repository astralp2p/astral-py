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

from typing import Any, AsyncIterator, Mapping, Sequence

from .. import querystring
from ..client import Client
from ..errors import ParseError, ProtocolError
from ..spec import Spec
from ..types import ObjectID

__all__ = ["ModuleClient"]


class ModuleClient:
    """One node module's ops, bound to one `Client`.

    **Naming conventions, decided here so thirteen modules do not each decide.**
    A method is the op name with `.` as `_`; the batch form of an op is
    `<op>_many`; the follow form is `<op>_follow`. Neither suffix is arbitrary:
    a suffix applies mechanically to every op name, where pluralising does not --
    `sign_hash` pluralises and `contains` does not -- and `<op>_follow` avoids the
    trap of a method named `follow` on which `Stream.follow()` is the one reader
    you must not use. Two conventions each for the same two shapes was the state
    this rule replaces: `Objects` used `_many`, `Crypto` pluralised, `Objects`
    prefixed `follow_`, `Services` suffixed `_follow` and `Tree` used a bare name.

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

    # --- argument marshalling, once (design section 5.1, rule 2) ---
    #
    # `_expect` was factored here and nothing else was, and the six modules that
    # landed after it grew **four spellings of the same parameter encoder** --
    # `_param(spec, value)` byte-identical in two files, `_encode(specs, values)`
    # byte-identical in two more, `_encode(values)` over a module-wide table, and
    # `_params(op, **values)` -- plus three copies of `_object_id` in two
    # behaviours. That last divergence was caller-visible: one form named the op
    # it failed in and the other did not, so `objects.probe('nope')` said which
    # op refused and `auth.index('nope')` did not. This is exactly what the class
    # docstring above says one base class exists to prevent.

    @staticmethod
    def _param(spec: Spec, value: Any) -> str:
        """One parameter value, in the bare payload half of its text encoding.

        Design section 5.1 rule 2: the parameter's type comes from the op's
        declaration, so it never travels, and `querystring.encode_param` is the
        single implementation. A spec is what makes it one -- without one the
        encoder dispatches on the *value*, so `b'ab'` silently becomes `YWI=`.
        """
        return querystring.encode_param(spec, value)

    @staticmethod
    def _encode(specs: Mapping[str, Spec], values: Mapping[str, Any]) -> dict[str, str]:
        """Every parameter through its declared spec.

        A key with no declared spec still travels, so nothing is silently
        dropped; what the declaration buys is that a wrong-typed value is refused
        here rather than encoded into a query the node reads as something else.
        """
        return querystring.encode_params(dict(specs), dict(values))

    async def _follow_pairs(
        self, context: Any, kind: type, op: str
    ) -> AsyncIterator[tuple[Any, bool]]:
        """`(object, live)` pairs from a follow stream, closed on exit.

        The iterator form of an ST+follow op, for a consumer that wants the pairs
        and not the stream. Closing is the iterator's: leaving the `async for` --
        by `break`, by exception, or by exhaustion -- closes the stream, because
        an undrained follow stream is one of the node's 32 workers held for the
        life of the process.

        Here rather than in one module, because it was `Services.updates()` alone
        and `Objects.scan_follow` and every follow op to come have exactly the
        call-site cost it exists to remove. One module's habit is how twelve
        modules end up copying it inconsistently or not at all.
        """
        async with context as stream:
            async for obj, live in stream.follow():
                yield self._expect(obj, kind, op), live

    @staticmethod
    def _object_id(value: ObjectID | str, op: str) -> ObjectID:
        """An `object_id.sha256` argument, from an ID or its `data1…` text form.

        The op is named in the failure, which is the form `objects.py` had and
        the two copies in `apphost.py` and `auth.py` did not: `'nope' has no
        'data1' prefix` does not say that `auth.index` is what refused it.
        """
        if isinstance(value, ObjectID):
            return value
        try:
            return ObjectID.parse(value)
        except ParseError as exc:
            raise ParseError(f"{op}: {value!r} is not an object id") from exc


def _name(kind: type) -> str:
    """A type's wire name, or its Python name when it has none."""
    return getattr(kind, "ASTRAL_TYPE", None) or kind.__name__
