"""Typed convenience wrappers around common astral protocols.

Each helper is exposed as an attribute of :class:`~astral.client.Client`
(``client.dir``, ``client.tree``, ``client.crypto``, ``client.objects``,
``client.apphost``). Helpers that return scalar common types work over every
transport; helpers that return structured objects (e.g. ``apphost.access_token``)
decode cleanly over the JSON transports (HTTP/WebSocket).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..client import Client

__all__ = ["Protocol", "Apphost", "Dir", "Tree", "Crypto", "Objects"]


class Protocol:
    """Base class holding a back-reference to the owning client."""

    def __init__(self, client: "Client") -> None:
        self.client = client


from .apphost import Apphost  # noqa: E402
from .crypto import Crypto  # noqa: E402
from .dir import Dir  # noqa: E402
from .objects import Objects  # noqa: E402
from .tree import Tree  # noqa: E402
