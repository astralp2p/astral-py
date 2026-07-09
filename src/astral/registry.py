"""Name-keyed registry of typed structured records — the decode blueprint table.

Mirrors astral-go's ``Blueprints``: each structured wire type registers under its
astral object-type string so the binary channel can decode it to a typed Python
value (a :class:`~astral.record.Record`) instead of raw bytes, while the JSON
transports reach the same classes through :meth:`~astral.record.Record.from_value`.
A record registers with the :func:`register` decorator — the Python analogue of
astral-go's per-type ``init()`` + ``astral.Add`` — and :func:`record_for` looks it
up. :func:`astral.payload.decode_payload` consults the registry on the binary path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Type

if TYPE_CHECKING:
    from .record import Record

__all__ = ["register", "record_for", "registered_types"]

_REGISTRY: "Dict[str, Type[Record]]" = {}


def register(obj_type: str) -> "Callable[[Type[Record]], Type[Record]]":
    """Class decorator registering a :class:`~astral.record.Record` under ``obj_type``.

    Re-registering the same class is idempotent; registering a *different* class
    under an already-taken type is a programming error and raises.
    """
    if not obj_type:
        raise ValueError("cannot register a record under an empty object type")

    def _decorate(cls: "Type[Record]") -> "Type[Record]":
        existing = _REGISTRY.get(obj_type)
        if existing is not None and existing is not cls:
            raise ValueError(
                f"object type {obj_type!r} already registered to {existing.__name__}"
            )
        _REGISTRY[obj_type] = cls
        return cls

    return _decorate


def record_for(obj_type: str) -> "Optional[Type[Record]]":
    """Return the record class registered for ``obj_type``, or ``None``."""
    return _REGISTRY.get(obj_type)


def registered_types() -> List[str]:
    """Return the sorted list of registered object types (diagnostics/tests)."""
    return sorted(_REGISTRY)
