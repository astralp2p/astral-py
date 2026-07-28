"""`shell`: the node's own op registry, as objects. One op, and it is the map.

`shell.spec` answers **every op every loaded module has registered** -- 118 of
them on `furry-bolt` -- each as a `routing.op_spec` carrying the op's name and
its declared parameters. It is how this SDK can check itself against any node
rather than against a document: the inventory in `survey-go-api.md` is a dump of
this op, and astral-go's own `module.go` constant lists disagree with it (the
survey's finding 10).

It answers **anonymously**, which is what makes it usable as a self-check: no
token, no claimed node, no state touched.

| Op | Mode | Answer | Effect |
|---|---|---|---|
| `shell.spec` | ST | `routing.op_spec` × n ++ `eos` | read-only |

**Two types, one of which the node cannot name.** `routing.op_spec` is
registered on the node and travels as a channel object. `query.field_spec` is
not: astral-go never calls `astral.Add` on `query.FieldSpec`, so it has no type
tag of its own and only ever appears inside an op spec's `Parameters` slice. It
is declared here under the name the blueprint would give it, because a `Slice`
needs an element type name, and a test asserts the node never sends one under
that name.

**Every string in both types is `string32`.** They are plain Go `string` fields
inside a reflectively-encoded struct, and `astral.Objectify` gives a bare
`string` a four-byte length prefix -- not `string8`, which is what a reader who
knows `astral.String8` expects to find. This is design section 9.2's D-9, the
highest-impact silent-corruption trap in the corpus, and `routing.op_spec` is
its pinned instance: one wrong width here desynchronises the payload and every
field after it decodes as something else. Verified against live bytes; the
capture and the assertion are `tests/test_risk_register.py::R14OpSpecStringWidth`.

The layout, decoded from those bytes::

    string32  Name
    uint32    len(Parameters)
      per parameter, a struct VALUE in a slice, so each carries the
      synthesized presence byte of design section 2.3:
        01
        string32  Name
        string32  Type       the astral type name of the parameter
        uint8     Required

**`Required` is not what the docs call required.** It is set only by a
`query:"required"` struct tag on the server's argument struct, and most
parameters the documentation describes as required carry no tag and are not
enforced. `required_params()` reports the enforced set, which is the only set a
caller can act on.

**`shell` is not a Tier-1 module** -- design section 0.1 excludes it as a module
and keeps this one op as an introspection helper, so `Shell` carries `spec` and
nothing else. Reached as `client.shell`, a `functools.cached_property` built on
first use.
"""

from __future__ import annotations

from typing import Any, Final, Sequence

from ..record import record, wire
from ..spec import Primitive, Slice
from .base import ModuleClient

__all__ = [
    "FieldSpec",
    "OP_SPEC",
    "OpSpec",
    "SHELL_TYPES",
    "Shell",
]

OP_SPEC: Final = "shell.spec"

# The type name `query.FieldSpec` would carry if astral-go registered it. It
# does not, so nothing on the wire ever bears this tag; it exists because a
# `Slice` names its element type and the registry resolves that name.
FIELD_SPEC_TYPE: Final = "query.field_spec"


# --- wire types ----------------------------------------------------------


@record(FIELD_SPEC_TYPE)
class FieldSpec:
    """One declared parameter of one op.

    `query.FieldSpec{Name string, Type string, Required bool}` in astral-go's
    `lib/query/editor.go`. Three plain Go fields, so two `string32`s and a
    `bool`, and it travels only inside `routing.op_spec`.

    `type` is the astral type name the node parses the argument as -- `string8`,
    `identity`, `bool` -- which is what tells a caller how to spell a value.
    """

    name: str = wire("Name", Primitive("string32"))
    type: str = wire("Type", Primitive("string32"))  # noqa: A003
    required: bool = wire("Required", Primitive("bool"))

    def __str__(self) -> str:
        return f"{self.name}:{self.type}{'*' if self.required else ''}"


@record("routing.op_spec")
class OpSpec:
    """One op and the parameters it declares.

    `{Name string, Parameters []query.FieldSpec}` in astral-go's
    `lib/routing/op_spec.go`. The parameters are struct **values** in a slice, so
    each element carries a synthesized presence byte (design section 2.3).
    """

    name: str = wire("Name", Primitive("string32"))
    parameters: list[FieldSpec] = wire("Parameters", Slice(FIELD_SPEC_TYPE))

    def __str__(self) -> str:
        joined = " ".join(str(p) for p in self.parameters)
        return f"{self.name} {joined}".rstrip()

    @property
    def module(self) -> str:
        """The module half of the op name, or `""` for a name with no dot."""
        head, dot, _rest = self.name.partition(".")
        return head if dot else ""

    def param(self, name: str) -> FieldSpec | None:
        """One declared parameter by name, or `None`.

        Case-sensitive, because the node's own matching is: `lib/query`'s
        `Editor.SetMany` drops a key it does not recognise in silence, so
        `Zone` and `zone` are not the same parameter and only one of them
        reaches the op.
        """
        for spec in self.parameters:
            if spec.name == name:
                return spec
        return None

    def required_params(self) -> list[str]:
        """The parameters the node **enforces**, which is not the documented set.

        `Required` comes from a `query:"required"` struct tag alone, and most
        parameters the documentation calls required carry none.
        """
        return [spec.name for spec in self.parameters if spec.required]


# --- the module client ---------------------------------------------------


class Shell(ModuleClient):
    """The `shell` module's one op, over one `Client`.

    Reached as `client.shell`, a cached property built on first use;
    `Shell(client)` constructs the same object directly. The scaffolding and the
    `**kw` contract are `ModuleClient`'s.
    """

    __slots__ = ()

    async def spec(self, **kw: Any) -> list[OpSpec]:
        """Every op the node has registered. ST, ends at `eos`.

        Anonymous and read-only. The answer is the node's whole routing table --
        118 specs on `furry-bolt` -- so it is one query and not one per module,
        and there is no per-module `.spec` op: `<module>.spec` answers
        `route_not_found` for every in-scope module, verified live.
        """
        return [
            self._expect(obj, OpSpec, OP_SPEC)
            for obj in await self._c.call(OP_SPEC, **kw)
        ]

    async def ops(self, **kw: Any) -> dict[str, OpSpec]:
        """`shell.spec` as a mapping from op name to spec.

        Op names are unique in the node's routing table -- registration is
        keyed by name -- so nothing is lost by the mapping, and a caller
        checking whether one op exists is not made to walk a list.
        """
        return {spec.name: spec for spec in await self.spec(**kw)}


SHELL_TYPES: Final[Sequence[type]] = (FieldSpec, OpSpec)
"""Every wire type this module declares, for a private-registry sweep."""

Shell.TYPES = SHELL_TYPES
