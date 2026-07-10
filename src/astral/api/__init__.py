"""The ``api`` package: typed per-protocol client helpers.

Each protocol lives in its own module (``api/apphost.py``, ``api/dir.py``, …);
its helper is exposed as an attribute of :class:`~astral.client.Client`
(``client.dir``, ``client.tree``, ``client.crypto``, ``client.objects``,
``client.apphost``). Helpers that return scalar common types work over every
transport; helpers that return structured objects (e.g. ``apphost.access_token``)
decode over both the binary channel (via the record registry) and the JSON
transports (HTTP/WebSocket).

Importing a protocol module fires its ``@register`` decorators, so this package
doubles as the record-registration aggregator (the astral-go ``pub.go`` analogue):
importing every submodule below makes their records decodable over binary IPC.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..client import Client

__all__ = ["Protocol", "Apphost", "Dir", "Tree", "Crypto", "Objects", "Ip", "Auth", "User"]


class Protocol:
    """Base class holding a back-reference to the owning client."""

    def __init__(self, client: "Client") -> None:
        self.client = client


from .apphost import Apphost  # noqa: E402
from .auth import Auth  # noqa: E402
from .crypto import Crypto  # noqa: E402
from .dir import Dir  # noqa: E402
from .ip import Ip  # noqa: E402
from .objects import Objects  # noqa: E402
from .tree import Tree  # noqa: E402
from .user import User  # noqa: E402
