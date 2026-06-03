"""Binary encoding primitives for the Astral wire format.

Reference: ``topics/binary-encoding.md`` and the ``common-types/`` directory of
astral-docs. The binary encoding is big-endian. Length-prefixed strings and
byte slices come in 8/16/32/64-bit-prefix flavours (``string8`` .. ``string64``,
``bytes8`` .. ``bytes64``); arrays use a ``uint32`` length prefix.

Two framings build on these primitives and are intentionally distinct:

* A *channel frame* (``core-primitives/channel.md``) is
  ``string8(type) ++ bytes32(payload)`` — see :mod:`astral.transport.binary`.
* The generic ``object`` field type (``common-types/object.md``) is
  ``string8(type) ++ payload`` with **no** length prefix on the payload, which
  stays self-delimiting because every concrete type knows its own length.
"""

from __future__ import annotations

import struct
from typing import Tuple

from .errors import EncodingError

__all__ = ["BinaryWriter", "BinaryReader", "IDENTITY_LEN", "ZERO_IDENTITY_HEX"]

# A compressed secp256k1 public key is 33 bytes / 66 hex digits (256-bit X
# coordinate + a sign byte; ``common-types/identity.md``). On the binary wire an
# identity is a bool presence flag followed by the 33 raw key bytes *only when
# present*: 0x01 + key (34 bytes) when set, or 0x00 (1 byte) for the null/zero
# identity. Verified against a live node's host_info_msg.
IDENTITY_LEN = 33
ZERO_IDENTITY_HEX = ""  # the API representation of the zero identity

_MAX = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}
_PACK = {8: ">B", 16: ">H", 32: ">I", 64: ">Q"}


class BinaryWriter:
    """Accumulates big-endian encoded values into a byte buffer."""

    def __init__(self) -> None:
        self._buf = bytearray()

    # -- raw ----------------------------------------------------------------
    def raw(self, data: bytes) -> "BinaryWriter":
        self._buf += data
        return self

    def getvalue(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    # -- unsigned integers --------------------------------------------------
    def u8(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">B", v & 0xFF))

    def u16(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">H", v & 0xFFFF))

    def u32(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">I", v & 0xFFFFFFFF))

    def u64(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF))

    # -- signed integers ----------------------------------------------------
    def i8(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">b", v))

    def i16(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">h", v))

    def i32(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">i", v))

    def i64(self, v: int) -> "BinaryWriter":
        return self.raw(struct.pack(">q", v))

    # -- bool ---------------------------------------------------------------
    def boolean(self, v: bool) -> "BinaryWriter":
        return self.u8(1 if v else 0)

    # -- length-prefixed bytes ---------------------------------------------
    def _lp_bytes(self, bits: int, data: bytes) -> "BinaryWriter":
        if len(data) > _MAX[bits]:
            raise EncodingError(
                f"value of {len(data)} bytes exceeds {bits}-bit length prefix"
            )
        self.raw(struct.pack(_PACK[bits], len(data)))
        return self.raw(data)

    def bytes8(self, data: bytes) -> "BinaryWriter":
        return self._lp_bytes(8, data)

    def bytes16(self, data: bytes) -> "BinaryWriter":
        return self._lp_bytes(16, data)

    def bytes32(self, data: bytes) -> "BinaryWriter":
        return self._lp_bytes(32, data)

    def bytes64(self, data: bytes) -> "BinaryWriter":
        return self._lp_bytes(64, data)

    # -- length-prefixed strings -------------------------------------------
    def string8(self, s: str) -> "BinaryWriter":
        return self._lp_bytes(8, s.encode("utf-8"))

    def string16(self, s: str) -> "BinaryWriter":
        return self._lp_bytes(16, s.encode("utf-8"))

    def string32(self, s: str) -> "BinaryWriter":
        return self._lp_bytes(32, s.encode("utf-8"))

    def string64(self, s: str) -> "BinaryWriter":
        return self._lp_bytes(64, s.encode("utf-8"))

    # -- domain types -------------------------------------------------------
    def identity(self, hex_str: str) -> "BinaryWriter":
        """Write an identity: a bool presence flag then the key when present.

        astrald encodes an identity as ``bool(present)`` followed by the 33 raw
        compressed-public-key bytes only when present. The null/zero identity
        (the empty string) is a single ``0x00`` byte. Verified against a live
        node's ``host_info_msg``.
        """
        if not hex_str:
            return self.u8(0)
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            raise EncodingError(
                f"identity must be a hex public key (resolve aliases first): {hex_str!r}"
            ) from None
        if len(data) != IDENTITY_LEN:
            raise EncodingError(
                f"identity must be {IDENTITY_LEN} bytes ({IDENTITY_LEN * 2} hex "
                f"digits), got {len(data)}"
            )
        return self.u8(1).raw(data)

    def nonce(self, value) -> "BinaryWriter":
        """Write a nonce64 as 8 raw bytes (accepts 16-hex str or int)."""
        return self.raw(_nonce_to_bytes(value))


class BinaryReader:
    """Reads big-endian encoded values from a byte buffer."""

    def __init__(self, data: bytes) -> None:
        self._data = memoryview(data)
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    def eof(self) -> bool:
        return self._pos >= len(self._data)

    def remaining(self) -> bytes:
        return bytes(self._data[self._pos :])

    def raw(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise EncodingError(
                f"unexpected end of data: wanted {n} bytes at offset {self._pos}, "
                f"have {len(self._data) - self._pos}"
            )
        out = bytes(self._data[self._pos : self._pos + n])
        self._pos += n
        return out

    def _unpack(self, fmt: str, n: int) -> int:
        return struct.unpack(fmt, self.raw(n))[0]

    # -- unsigned integers --------------------------------------------------
    def u8(self) -> int:
        return self._unpack(">B", 1)

    def u16(self) -> int:
        return self._unpack(">H", 2)

    def u32(self) -> int:
        return self._unpack(">I", 4)

    def u64(self) -> int:
        return self._unpack(">Q", 8)

    # -- signed integers ----------------------------------------------------
    def i8(self) -> int:
        return self._unpack(">b", 1)

    def i16(self) -> int:
        return self._unpack(">h", 2)

    def i32(self) -> int:
        return self._unpack(">i", 4)

    def i64(self) -> int:
        return self._unpack(">q", 8)

    # -- bool ---------------------------------------------------------------
    def boolean(self) -> bool:
        return self.u8() != 0

    # -- length-prefixed bytes/strings -------------------------------------
    def _lp(self, bits: int) -> bytes:
        n = self._unpack(_PACK[bits], bits // 8)
        return self.raw(n)

    def bytes8(self) -> bytes:
        return self._lp(8)

    def bytes16(self) -> bytes:
        return self._lp(16)

    def bytes32(self) -> bytes:
        return self._lp(32)

    def bytes64(self) -> bytes:
        return self._lp(64)

    def string8(self) -> str:
        return self._lp(8).decode("utf-8")

    def string16(self) -> str:
        return self._lp(16).decode("utf-8")

    def string32(self) -> str:
        return self._lp(32).decode("utf-8")

    def string64(self) -> str:
        return self._lp(64).decode("utf-8")

    # -- domain types -------------------------------------------------------
    def identity(self) -> str:
        """Read an identity: a bool presence flag, then the key when present.

        Returns the 66-hex-digit public key, or ``""`` for the null identity
        (presence flag ``0``, with no key bytes following).
        """
        if self.u8() == 0:
            return ZERO_IDENTITY_HEX
        return self.raw(IDENTITY_LEN).hex()

    def nonce(self) -> str:
        """Read a nonce64 and return its 16-digit hex string."""
        return self.raw(8).hex()


def _nonce_to_bytes(value) -> bytes:
    """Coerce a nonce64 (16-hex string or int) to its 8 raw bytes."""
    if isinstance(value, bytes):
        if len(value) != 8:
            raise EncodingError("nonce must be 8 bytes")
        return value
    if isinstance(value, int):
        return value.to_bytes(8, "big")
    data = bytes.fromhex(str(value))
    if len(data) != 8:
        raise EncodingError("nonce64 must be a 16-digit hex string")
    return data


def channel_frame(obj_type: str, payload: bytes) -> bytes:
    """Encode one channel frame: ``string8(type) ++ bytes32(payload)``."""
    return BinaryWriter().string8(obj_type).bytes32(payload).getvalue()


def read_channel_frame(reader: BinaryReader) -> Tuple[str, bytes]:
    """Decode one channel frame from ``reader``."""
    obj_type = reader.string8()
    payload = reader.bytes32()
    return obj_type, payload
