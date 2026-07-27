"""The record declaration syntax and the one field walker every codec shares.

A record is a dataclass whose fields carry their wire spec in
`field(metadata=...)`. One declaration site, no duplication, order guaranteed by
`dataclasses.fields()`:

    @record("mod.apphost.route_query_msg")
    class RouteQueryMsg:
        nonce:   Nonce           = wire("Nonce",   Primitive("nonce64"))
        caller:  Identity | None = wire("Caller",  Ptr("identity"))
        target:  Identity | None = wire("Target",  Ptr("identity"))
        query:   str             = wire("Query",   Primitive("string16"))
        zone:    Zone            = wire("Zone",    Primitive("zone"), default=Zone.ALL)
        filters: list[str]       = wire("Filters", Slice("string8"))

`@record(t)` applies `@dataclass(slots=True, kw_only=True, eq=True, repr=True)`,
reads the declared fields into `cls.FIELDS`, sets `cls.ASTRAL_TYPE`, validates
the whole thing, and registers the class. `kw_only=True` removes the
"defaults must come last" constraint entirely; positional construction of wire
messages is a bug farm and is not offered.

`cls.FIELDS` is the single schema. `codec.binary` walks it for binary, a JSON
codec walks it keyed by `wire_name`, a text codec walks it for the text form,
and `blueprint.of(cls)` turns it into an `astral.blueprint` object. A fifth
facade costs one function, not N types.

An embedded struct needs no new spec kind: a value embed is `Ref(type)` and a
pointer embed is `Ptr(type)`, both named for the Go *type*, because that is the
name astral-go's JSON uses for an embedded field. Binary flattening and JSON
nesting then fall out of the existing rules.

The escape hatch: a record that defines `write_payload` / `read_payload` in its
own body keeps them. `FIELDS` then serves JSON only and `DERIVABLE` is `False`.
Four wire types need it and no others are permitted without amending the design:
`mod.tor.endpoint`, `mod.nodes.node_info`, `bip137sig.entropy` and
`mod.ip.ip_address`.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, ClassVar, NamedTuple, Self, TypeVar

from .codec.binary import read_fields, spec_zero, write_fields
from .errors import CycleDetected, SchemaError
from .primitives import SCALARS
from .registry import Blueprints, default_blueprints
from .spec import PRIMITIVE_TYPES, Ptr, Ref, Spec, validate_name, validate_spec
from .wire import Reader, Writer

__all__ = ["AliasRecord", "F", "alias", "embed", "fields_of", "record", "wire"]

_KEY = "astral"


class F(NamedTuple):
    """One field of a record: the Python attribute, the wire name, the spec.

    The wire name is PascalCase and reaches JSON and text only. Binary carries
    order and nothing else.
    """

    attr: str
    wire_name: str
    spec: Spec


class _Unset:
    __slots__ = ()

    def __repr__(self) -> str:
        return "UNSET"


_UNSET = _Unset()


class _Wire(NamedTuple):
    """The `wire()` declaration, parked in the dataclass field metadata."""

    wire_name: str
    spec: Spec
    embed: bool


class _ZeroFactory:
    """The spec-zero, resolved at construction rather than at declaration.

    A `Ref` to a type that is not registered yet must not fail at class-creation
    time, so the factory is lazy and the registry is bound by `@record`.
    """

    __slots__ = ("spec", "registry")

    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        self.registry: Blueprints | None = None

    def __call__(self) -> Any:
        return spec_zero(self.spec, self.registry)


def wire(name: str, spec: Spec, *, default: Any = _UNSET) -> Any:
    """Declare a wire field.

    `name` is the PascalCase JSON and text name; `spec` is the wire shape. With
    `default` omitted the spec-zero is used, so field order is never constrained
    by dataclass default rules.
    """
    validate_name(name, "field name")
    validate_spec(spec)
    metadata = {_KEY: _Wire(name, spec, False)}
    if isinstance(default, _Unset):
        return dataclasses.field(default_factory=_ZeroFactory(spec), metadata=metadata)
    if isinstance(default, (list, dict, set, bytearray)):
        return dataclasses.field(
            default_factory=lambda value=default: type(value)(value),  # type: ignore[misc]
            metadata=metadata,
        )
    return dataclasses.field(default=default, metadata=metadata)


def embed(name: str, type: str, *, optional: bool = False) -> Any:  # noqa: A002
    """Declare an embedded struct.

    `name` is the Go type name, which is the name astral-go's JSON uses for an
    embedded field. A value embed flattens on the binary wire; a pointer embed
    is a nil flag plus the inlined payload. The enclosing record forwards
    attribute lookups into the embedded value, so reaching through the embed is
    never necessary.
    """
    spec: Spec = Ptr(type) if optional else Ref(type)
    validate_name(name, "field name")
    metadata = {_KEY: _Wire(name, spec, True)}
    if optional:
        return dataclasses.field(default=None, metadata=metadata)
    return dataclasses.field(default_factory=_ZeroFactory(spec), metadata=metadata)


def fields_of(cls: type) -> tuple[F, ...]:
    """The record's schema, or `()` for a class that carries none."""
    return tuple(getattr(cls, "FIELDS", ()))


T = TypeVar("T")


def record(type_name: str, *, registry: Blueprints | None = None) -> Callable[[type[T]], type[T]]:
    """Turn a class body of `wire()` declarations into a registered record."""

    def decorate(cls: type[T]) -> type[T]:
        target = default_blueprints() if registry is None else registry
        _bind_zero_factories(cls, target)
        custom = "write_payload" in cls.__dict__ or "read_payload" in cls.__dict__
        if custom and not (
            "write_payload" in cls.__dict__ and "read_payload" in cls.__dict__
        ):
            raise SchemaError(f"{type_name}: a custom codec must define both halves")

        built: Any = dataclasses.dataclass(slots=True, kw_only=True, eq=True, repr=True)(cls)

        schema: list[F] = []
        embeds: list[str] = []
        for field in dataclasses.fields(built):
            declaration = field.metadata.get(_KEY)
            if declaration is None:
                continue
            schema.append(F(field.name, declaration.wire_name, declaration.spec))
            if declaration.embed:
                embeds.append(field.name)

        built.ASTRAL_TYPE = type_name
        built.FIELDS = tuple(schema)
        built.DERIVABLE = not custom
        _validate(type_name, built.FIELDS)

        if not custom:
            built.write_payload = _write_payload
            built.read_payload = classmethod(_read_payload)
        if embeds:
            _install_forwarding(built, tuple(embeds))

        target.add(built)
        return built

    return decorate


def alias(type_name: str, underlying: str, *, registry: Blueprints | None = None) -> type:
    """Declare an alias-kind type: the underlying primitive's bytes, a new name.

    The alias name lives in the registry and surfaces through `ASTRAL_TYPE`. It
    never reaches the wire.
    """
    validate_name(type_name, "type name")
    if underlying not in PRIMITIVE_TYPES:
        raise SchemaError(f"{type_name}: underlying {underlying!r} is not a primitive type")
    class_name = "".join(part.title() for part in type_name.replace(".", "_").split("_"))
    built = type(
        class_name or "Alias",
        (AliasRecord,),
        {
            "__slots__": (),
            "ASTRAL_TYPE": type_name,
            "UNDERLYING": underlying,
            "__doc__": f"Alias of {underlying}, registered as {type_name}.",
        },
    )
    (default_blueprints() if registry is None else registry).add(built)
    return built


class AliasRecord:
    """An alias-kind value: one primitive payload under a distinct type name."""

    __slots__ = ("value",)

    ASTRAL_TYPE: ClassVar[str] = ""
    UNDERLYING: ClassVar[str] = ""
    FIELDS: ClassVar[tuple[F, ...]] = ()
    DERIVABLE: ClassVar[bool] = True

    def __init__(self, value: Any = None) -> None:
        self.value = SCALARS[self.UNDERLYING].zero() if value is None else value

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.value!r})"

    def __eq__(self, other: object) -> bool:
        return type(self) is type(other) and self.value == other.value  # type: ignore[attr-defined]

    def __hash__(self) -> int:
        return hash((type(self).ASTRAL_TYPE, self.value))

    @classmethod
    def read_payload(cls, r: Reader) -> Self:
        return cls(SCALARS[cls.UNDERLYING].read(r))

    def write_payload(self, w: Writer) -> None:
        SCALARS[self.UNDERLYING].write(w, self.value)


# --- the generated codec ------------------------------------------------


def _write_payload(self: Any, w: Writer) -> None:
    write_fields(w, type(self).FIELDS, self)


def _read_payload(cls: Any, r: Reader) -> Any:
    return cls(**read_fields(r, cls.FIELDS))


# --- declaration mechanics ----------------------------------------------


def _bind_zero_factories(cls: type, registry: Blueprints) -> None:
    """Point every lazy spec-zero at the registry this record registers in.

    The binding happens before `@dataclass` runs, because the generated
    `__init__` captures the factory object at that moment.
    """
    for value in vars(cls).values():
        if not isinstance(value, dataclasses.Field):
            continue
        if value.metadata.get(_KEY) is None:
            continue
        factory = value.default_factory
        if isinstance(factory, _ZeroFactory):
            factory.registry = registry


def _validate(type_name: str, schema: tuple[F, ...]) -> None:
    validate_name(type_name, "type name")
    seen: dict[str, str] = {}
    for field in schema:
        validate_name(field.wire_name, "field name")
        validate_spec(field.spec)
        folded = field.wire_name.lower()
        if folded in seen:
            # Folded, because the JSON decoder matches case-insensitively: a
            # schema the binary codec accepts must round-trip through JSON too.
            raise SchemaError(
                f"{type_name}: fields {seen[folded]!r} and {field.wire_name!r} "
                "differ only in case"
            )
        seen[folded] = field.wire_name
        if isinstance(field.spec, (Ref, Ptr)) and field.spec.type == type_name:
            raise CycleDetected(f"{type_name}: field {field.wire_name!r} references itself")


def _install_forwarding(cls: type, embeds: tuple[str, ...]) -> None:
    """Forward an unknown attribute into the embedded values, in order."""

    def __getattr__(self: Any, item: str) -> Any:
        if item.startswith("_") or item in ("FIELDS", "ASTRAL_TYPE"):
            raise AttributeError(item)
        for attr in embeds:
            try:
                inner = object.__getattribute__(self, attr)
            except AttributeError:
                continue
            if inner is not None and hasattr(inner, item):
                return getattr(inner, item)
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {item!r}")

    cls.__getattr__ = __getattr__  # type: ignore[attr-defined]
