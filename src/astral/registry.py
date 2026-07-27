"""Blueprints: the type-name registry.

One dict per registry level, keyed by Object Type name, holding either a
compile-time prototype (a record or scalar-object *class*) or a runtime
blueprint (an object satisfying `RuntimeBlueprint`, which `astral.blueprint`
supplies). A registry may name a parent; every lookup walks the chain.

Rules ported verbatim from astral-go's `Blueprints`:

- A name is unique across the whole parent chain. A child cannot shadow a
  parent.
- An empty type name is rejected. `new("")` returns `None`.
- Registering a blueprint validates it, checks closure -- every referenced type
  already registered -- clones it, stores it, and returns the ObjectID of its
  canonical form.

The registry travels with the decode call, never as a module global: the codec
threads it into every nested frame, so a per-call registry scopes an entire
object graph.

One rule is stricter than astral-go: a `Ref`/`Ptr` cycle of any length is
rejected at registration. astral-go catches only one-step self-reference and
stack-overflows on a mutual pair (astral-go bug G-22).
"""

from __future__ import annotations

import contextvars
from typing import TYPE_CHECKING, Any, Iterable, Protocol, runtime_checkable

from .errors import BlueprintNotFound, CycleDetected, DepthExceeded, SchemaError
from .spec import MAX_DEPTH, Ptr, Ref, Spec, referenced_type, validate_name, validate_spec

if TYPE_CHECKING:
    from .types import ObjectID

__all__ = ["Blueprints", "RuntimeBlueprint", "default_blueprints"]


@runtime_checkable
class RuntimeBlueprint(Protocol):
    """A schema that arrived at runtime rather than as a class body.

    `astral.blueprint.Blueprint` satisfies this. The registry owns the
    registration policy and reads the schema through these six members only.
    """

    def blueprint_name(self) -> str:
        """The type name this blueprint registers under."""

    def blueprint_specs(self) -> tuple[Spec, ...]:
        """One spec per field, in declaration order. Empty for an alias kind."""

    def blueprint_underlying(self) -> str:
        """The underlying primitive for an alias kind, `""` for a struct kind."""

    def validate(self) -> None:
        """Raise `SchemaError` unless the blueprint is well formed."""

    def clone(self) -> "RuntimeBlueprint":
        """A copy the caller cannot mutate through."""

    def new(self) -> Any:
        """A zero value bound to this blueprint."""


# Construction depth. A `Ref` cycle recurses through spec-zero construction, so
# `new()` counts frames exactly as the codec counts I/O frames. A ContextVar
# rather than a plain counter: each thread and each task starts at zero, and the
# count cannot leak across an abandoned decode.
_depth: contextvars.ContextVar[int] = contextvars.ContextVar("astral_construction_depth", default=0)


def _specs_of(entry: Any) -> tuple[Spec, ...]:
    """The spec of each field of a registry entry, prototype or runtime alike."""
    if isinstance(entry, type):
        return tuple(f.spec for f in getattr(entry, "FIELDS", ()))
    return tuple(entry.blueprint_specs())


def _underlying_of(entry: Any) -> str:
    if isinstance(entry, type):
        return str(getattr(entry, "UNDERLYING", ""))
    return entry.blueprint_underlying()


class Blueprints:
    """A type-name registry with an optional parent."""

    __slots__ = ("_entries", "parent")

    def __init__(self, parent: "Blueprints | None" = None) -> None:
        self._entries: dict[str, Any] = {}
        self.parent: Blueprints | None = parent

    def __repr__(self) -> str:
        return f"Blueprints({len(self._entries)} types, parent={self.parent is not None})"

    # --- lookup ---

    def has(self, type_name: str) -> bool:
        """Whether the name is registered anywhere in the chain."""
        if type_name in self._entries:
            return True
        return self.parent is not None and self.parent.has(type_name)

    def find(self, type_name: str) -> Any | None:
        """The entry registered under the name, walking the chain."""
        entry = self._entries.get(type_name)
        if entry is not None:
            return entry
        return self.parent.find(type_name) if self.parent is not None else None

    def new(self, type_name: str) -> Any | None:
        """A zero value of the named type, or `None` when the name is unknown.

        Construction is depth-guarded: a runtime blueprint whose fields
        reference one another materialises one nested zero value per frame.
        """
        if not type_name:
            return None
        entry = self.find(type_name)
        if entry is None:
            return None
        depth = _depth.get()
        if depth >= MAX_DEPTH:
            raise DepthExceeded(f"construction of {type_name} passed depth {MAX_DEPTH}")
        token = _depth.set(depth + 1)
        try:
            if not isinstance(entry, type):
                return entry.new()
            # ASTRAL_ZERO is the hook for a class no zero-argument call can
            # construct. `Zone` is the only one: an enum class always demands a
            # value.
            zero = getattr(entry, "ASTRAL_ZERO", None)
            return zero() if zero is not None else entry()
        finally:
            _depth.reset(token)

    def blueprint(self, type_name: str) -> RuntimeBlueprint | None:
        """The runtime blueprint registered under the name, or `None`.

        A compile-time prototype yields `None`: it has no runtime blueprint
        until `astral.blueprint` derives one from its `FIELDS`.
        """
        entry = self.find(type_name)
        if entry is None or isinstance(entry, type):
            return None
        return entry

    def require(self, type_name: str) -> Any:
        """The entry, or `BlueprintNotFound`."""
        entry = self.find(type_name)
        if entry is None:
            raise BlueprintNotFound(type_name)
        return entry

    # --- registration ---

    def add(self, *classes: type) -> None:
        """Register compile-time prototypes.

        Every name is validated before any insertion, so a rejected batch
        leaves the registry as it was.
        """
        for cls in classes:
            name = getattr(cls, "ASTRAL_TYPE", "")
            if not name:
                raise SchemaError(f"{cls.__name__}: object type is empty")
            validate_name(name, "type name")
            if self.has(name):
                raise SchemaError(f"blueprint for {name} already added")
        seen: set[str] = set()
        for cls in classes:
            name = cls.ASTRAL_TYPE  # type: ignore[attr-defined]
            if name in seen:
                raise SchemaError(f"blueprint for {name} already added")
            seen.add(name)
        for cls in classes:
            name = cls.ASTRAL_TYPE  # type: ignore[attr-defined]
            self._check_cycles(name, _specs_of(cls))
            self._entries[name] = cls

    def register_blueprint(self, bp: RuntimeBlueprint) -> "ObjectID":
        """Register a runtime blueprint and return the ObjectID of its canonical form.

        Validation, then a name-collision check across the chain, then closure:
        every referenced type must already be registered, which forbids a
        dangling reference and forces a peer to register prerequisites first.
        The stored blueprint is a clone, so later mutation of the argument
        cannot retroactively change constructed values or orphan the returned
        ObjectID.
        """
        bp.validate()
        name = bp.blueprint_name()
        validate_name(name, "type name")
        if self.has(name):
            raise SchemaError(f"blueprint for {name} already added")

        underlying = bp.blueprint_underlying()
        specs = tuple(bp.blueprint_specs())
        if underlying:
            if specs:
                raise SchemaError(f"{name}: kind ambiguous -- both fields and underlying set")
            if not self.has(underlying):
                raise SchemaError(f"{name}: underlying {underlying} is not registered")
        else:
            for spec in specs:
                validate_spec(spec)
                ref = referenced_type(spec)
                if ref and not self.has(ref):
                    raise SchemaError(f"{name}: references unregistered type {ref}")
            self._check_cycles(name, specs)

        stored = bp.clone()
        self._entries[name] = stored
        # objectid.py owns both ID paths; the import is local because the
        # registry sits below the codec layer in the dependency order.
        from .objectid import object_id

        return object_id(stored)

    # --- ordering ---

    def ordered(self) -> list[str]:
        """Every registered name in dependency order, for a blueprint sync.

        Parent levels first. Within a level: struct-kind prototypes
        alphabetically, then aliases alphabetically, then runtime struct
        blueprints topologically sorted by referenced type with an alphabetical
        tie-break. An alias precedes any blueprint that references it.

        A reference cycle cannot be registered, so the topological sort has no
        cycle to report.
        """
        out: list[str] = []
        seen: set[str] = set()
        if self.parent is not None:
            for name in self.parent.ordered():
                if name not in seen:
                    out.append(name)
                    seen.add(name)

        protos: list[str] = []
        aliases: list[str] = []
        runtime: list[str] = []
        for name, entry in self._entries.items():
            if name in seen:
                continue
            if _underlying_of(entry):
                aliases.append(name)
            elif isinstance(entry, type):
                protos.append(name)
            else:
                runtime.append(name)

        out += sorted(protos)
        out += sorted(aliases)
        out += self._topological(runtime)
        return out

    def _topological(self, names: Iterable[str]) -> list[str]:
        pending = sorted(names)
        in_set = set(pending)
        in_degree = {name: 0 for name in pending}
        dependents: dict[str, list[str]] = {name: [] for name in pending}
        for name in pending:
            for spec in _specs_of(self.find(name)):
                ref = referenced_type(spec)
                if ref and ref != name and ref in in_set:
                    dependents[ref].append(name)
                    in_degree[name] += 1

        out: list[str] = []
        emitted: set[str] = set()
        while len(out) < len(pending):
            progress = False
            for name in pending:
                if name in emitted or in_degree[name] != 0:
                    continue
                out.append(name)
                emitted.add(name)
                for dependent in dependents[name]:
                    in_degree[dependent] -= 1
                progress = True
            if not progress:
                out += [name for name in pending if name not in emitted]
                break
        return out

    # --- cycle detection ---

    def _check_cycles(self, name: str, specs: tuple[Spec, ...]) -> None:
        """Reject a `Ref`/`Ptr` cycle of any length reachable from `name`.

        Only `Ref` and `Ptr` recurse through construction: a `Ref` consumes zero
        bytes per frame and a `Ptr` one, so a cycle through either is unbounded.
        A cycle through `Slice`, `Array` or `Map` is bounded by the wire count
        and stays legal, matching astral-go.
        """
        stack: list[str] = [name]
        self._walk_refs(name, specs, stack, set())

    def _walk_refs(
        self, origin: str, specs: tuple[Spec, ...], stack: list[str], done: set[str]
    ) -> None:
        for spec in specs:
            if not isinstance(spec, (Ref, Ptr)):
                continue
            target = spec.type
            if target in stack:
                raise CycleDetected(f"{origin}: {' -> '.join(stack)} -> {target}")
            if target in done:
                continue
            entry = self.find(target)
            if entry is None:
                continue
            stack.append(target)
            self._walk_refs(origin, _specs_of(entry), stack, done)
            stack.pop()
            done.add(target)


_default = Blueprints()


def default_blueprints() -> Blueprints:
    """The process-wide registry every declared type registers itself in."""
    return _default
