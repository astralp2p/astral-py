"""astral -- an asyncio client for the astrald apphost IPC protocol.

The public facade lands with the client layer. Until then this module exports
nothing.

Importing the package registers every wire-core type, so a decode never depends
on which submodule a caller happened to import first. Module types register
themselves the same way, one import deeper: importing `astral.api` guarantees
every `mod.*` type is registered.
"""

from __future__ import annotations

from . import object as _object  # noqa: F401 -- registers the wire-core types

__version__ = "0.1.0"

__all__: list[str] = []
