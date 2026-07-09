"""The ``ip`` protocol: local/public IP addresses and the default gateway.

Reference: ``protocols/ip/``. The three ops return ``mod.ip.ip_address``
objects: ``ip.default_gateway`` returns a single address, ``ip.local_addrs`` and
``ip.public_ip_candidates`` stream addresses terminated by ``eos``.

``mod.ip.ip_address`` has no named struct fields — it is a bare astral ``bytes8``
(a ``uint8`` length prefix followed by 4 IPv4 or 16 IPv6 bytes). So it is *not*
registered as a :class:`~astral.record.Record`: over the JSON transports the
envelope ``Object`` is already the dotted/colon IP string, and over the binary
channel it decodes (as an unregistered structured type) to the raw ``bytes8``
payload. :func:`_ip_str` normalizes both forms to a clean IP string.
"""

from __future__ import annotations

import socket
from typing import List

from . import Protocol

__all__ = ["Ip"]


def _ip_str(value) -> str:
    """Normalize a ``mod.ip.ip_address`` value to a clean IP string.

    JSON path: the envelope ``Object`` is already the IP string, so it is
    returned unchanged. Binary path: ``value`` is the raw ``bytes8`` payload — a
    1-byte length prefix followed by 4 (IPv4) or 16 (IPv6) address bytes — so the
    prefix is dropped and the remaining bytes are formatted with
    :func:`socket.inet_ntop`, choosing the family by length.

    The exact ``bytes8`` form (the leading length byte and the 4/16-byte body)
    is inferred from the docs and is live-node-unconfirmed.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value[1:])  # drop the uint8 length prefix
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        if len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
        raise ValueError(f"mod.ip.ip_address: unexpected address length {len(raw)}")
    raise TypeError(f"cannot decode mod.ip.ip_address from {type(value).__name__}")


class Ip(Protocol):
    """Typed helpers for the ``ip`` protocol (all 3 documented ops)."""

    def default_gateway(self) -> str:
        """Return the default network gateway's IP address."""
        return _ip_str(self.client.call_one("ip.default_gateway"))

    def local_addrs(self) -> List[str]:
        """Stream the local interface IP addresses (loopback excluded)."""
        return [_ip_str(o.value) for o in self.client.call("ip.local_addrs")]

    def public_ip_candidates(self) -> List[str]:
        """Stream the candidate public IP addresses for the local node."""
        return [_ip_str(o.value) for o in self.client.call("ip.public_ip_candidates")]
