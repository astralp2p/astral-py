"""Byte-level reading and writing for the astral wire format.

Big-endian everywhere, two's complement for signed integers, IEEE 754 for
floats. No varints, no alignment, no padding, and no field names: order is the
schema. This is the only module in the package that touches `struct`.

Byte counts are not returned. Callers derive them from `Reader.pos` and
`len(Writer)`; astral-go's `n` values are wrong for eight types and reproducing
them would be reproducing a bug.

Two rules the whole core depends on:

- A read past the end raises `ShortRead` and assigns nothing.
- Every length-prefixed read checks the declared length against `max_alloc`
  before allocating, and every length-prefixed write buffers its payload,
  checks the width cap, then writes. A rejected write leaves the buffer
  untouched.
"""

from __future__ import annotations

import struct
from typing import Final

from .errors import AllocationLimit, InvalidFlag, RangeError, ShortRead, ValueTooLarge

__all__ = ["DEFAULT_MAX_ALLOC", "Reader", "Writer"]

DEFAULT_MAX_ALLOC: Final = 64 * 1024 * 1024

_F32: Final = struct.Struct(">f")
_F64: Final = struct.Struct(">d")

_ENCODING: Final = "utf-8"
# Go strings are byte containers. surrogateescape is the only error handler that
# round-trips arbitrary bytes through `str` byte-exactly, which ObjectID
# stability requires. "replace" would silently corrupt content hashes.
_ERRORS: Final = "surrogateescape"


class Reader:
    """A cursor over a bytes buffer.

    A reader is bounded to exactly the bytes it may consume. Types that read to
    the end of their input -- `Blob`, `UnparsedObject` -- must therefore be
    handed a reader over one frame's payload and never the socket.
    """

    __slots__ = ("_data", "_pos", "_end", "max_alloc")

    def __init__(
        self,
        data: bytes | bytearray | memoryview,
        *,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        start: int = 0,
        end: int | None = None,
    ) -> None:
        self._data: bytes = data if isinstance(data, bytes) else bytes(data)
        self._pos: int = start
        self._end: int = len(self._data) if end is None else end
        self.max_alloc: int = max_alloc

    def __repr__(self) -> str:
        return f"Reader(pos={self._pos}, remaining={self.remaining})"

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    @property
    def at_end(self) -> bool:
        return self._pos >= self._end

    def raw(self, n: int) -> bytes:
        """Read exactly `n` bytes."""
        if n < 0:
            raise ValueError(f"negative read length {n}")
        stop = self._pos + n
        if stop > self._end:
            raise ShortRead(
                f"short read: wanted {n} bytes at offset {self._pos}, {self.remaining} available"
            )
        out = self._data[self._pos : stop]
        self._pos = stop
        return out

    def rest(self) -> bytes:
        """Read everything left. The greedy read `Blob` and `UnparsedObject` use."""
        out = self._data[self._pos : self._end]
        self._pos = self._end
        return out

    def skip(self, n: int) -> None:
        self.raw(n)

    def bounded(self, n: int) -> "Reader":
        """Consume `n` bytes and return a reader over just those bytes."""
        if n < 0:
            raise ValueError(f"negative window length {n}")
        stop = self._pos + n
        if stop > self._end:
            raise ShortRead(
                f"short read: wanted a {n}-byte window at offset {self._pos}, "
                f"{self.remaining} available"
            )
        window = Reader(
            self._data, max_alloc=self.max_alloc, start=self._pos, end=stop
        )
        self._pos = stop
        return window

    # --- unsigned integers ---

    def uint8(self) -> int:
        return self.raw(1)[0]

    def uint16(self) -> int:
        return int.from_bytes(self.raw(2), "big")

    def uint32(self) -> int:
        return int.from_bytes(self.raw(4), "big")

    def uint64(self) -> int:
        return int.from_bytes(self.raw(8), "big")

    # --- signed integers ---

    def int8(self) -> int:
        return int.from_bytes(self.raw(1), "big", signed=True)

    def int16(self) -> int:
        return int.from_bytes(self.raw(2), "big", signed=True)

    def int32(self) -> int:
        return int.from_bytes(self.raw(4), "big", signed=True)

    def int64(self) -> int:
        return int.from_bytes(self.raw(8), "big", signed=True)

    # --- floats ---

    def float32(self) -> float:
        return _F32.unpack(self.raw(4))[0]

    def float64(self) -> float:
        return _F64.unpack(self.raw(8))[0]

    # --- single bytes with two different strictness rules ---

    def boolean(self) -> bool:
        """A `bool` payload. Any non-zero byte is true."""
        return self.raw(1)[0] != 0

    def flag(self) -> bool:
        """A pointer nil flag or a container presence byte. Only 0x00 or 0x01.

        Read-side leniency stops here: 0x00 means absent and 0x01 means present,
        in both the pointer and the synthesized-presence positions. Anything
        else is corrupt, because the value bytes that follow cannot be located.
        """
        b = self.raw(1)[0]
        if b > 1:
            raise InvalidFlag(f"invalid presence flag 0x{b:02x} at offset {self._pos - 1}")
        return b == 1

    # --- length-prefixed ---

    def _length(self, name: str, width: int) -> int:
        v = int.from_bytes(self.raw(width), "big")
        if v > self.max_alloc:
            raise AllocationLimit(
                f"{name}: declared length {v} exceeds max_alloc {self.max_alloc}"
            )
        return v

    def string8(self) -> str:
        return self.raw(self._length("string8", 1)).decode(_ENCODING, _ERRORS)

    def string16(self) -> str:
        return self.raw(self._length("string16", 2)).decode(_ENCODING, _ERRORS)

    def string32(self) -> str:
        return self.raw(self._length("string32", 4)).decode(_ENCODING, _ERRORS)

    def string64(self) -> str:
        return self.raw(self._length("string64", 8)).decode(_ENCODING, _ERRORS)

    def bytes8(self) -> bytes:
        return self.raw(self._length("bytes8", 1))

    def bytes16(self) -> bytes:
        return self.raw(self._length("bytes16", 2))

    def bytes32(self) -> bytes:
        return self.raw(self._length("bytes32", 4))

    def bytes64(self) -> bytes:
        return self.raw(self._length("bytes64", 8))


class Writer:
    """An append-only buffer.

    A frame is serialised into one `Writer` and issued as a single
    `transport.write()`, which is what makes a write lock unnecessary anywhere
    in the SDK.
    """

    __slots__ = ("_buf",)

    def __init__(self, buf: bytearray | None = None) -> None:
        self._buf: bytearray = bytearray() if buf is None else buf

    def __repr__(self) -> str:
        return f"Writer({len(self._buf)} bytes)"

    def __len__(self) -> int:
        return len(self._buf)

    def __bytes__(self) -> bytes:
        return bytes(self._buf)

    def getvalue(self) -> bytes:
        return bytes(self._buf)

    @property
    def buffer(self) -> bytearray:
        """The live buffer. Written into directly by frame assembly."""
        return self._buf

    def raw(self, data: bytes | bytearray | memoryview) -> None:
        self._buf += data

    # --- unsigned integers ---

    def uint8(self, value: int) -> None:
        self._uint("uint8", 1, value)

    def uint16(self, value: int) -> None:
        self._uint("uint16", 2, value)

    def uint32(self, value: int) -> None:
        self._uint("uint32", 4, value)

    def uint64(self, value: int) -> None:
        self._uint("uint64", 8, value)

    def _uint(self, name: str, width: int, value: int) -> None:
        if not 0 <= value < (1 << (8 * width)):
            raise RangeError(f"{name}: {value} out of range")
        self._buf += value.to_bytes(width, "big")

    # --- signed integers ---

    def int8(self, value: int) -> None:
        self._int("int8", 1, value)

    def int16(self, value: int) -> None:
        self._int("int16", 2, value)

    def int32(self, value: int) -> None:
        self._int("int32", 4, value)

    def int64(self, value: int) -> None:
        self._int("int64", 8, value)

    def _int(self, name: str, width: int, value: int) -> None:
        bound = 1 << (8 * width - 1)
        if not -bound <= value < bound:
            raise RangeError(f"{name}: {value} out of range")
        self._buf += value.to_bytes(width, "big", signed=True)

    # --- floats ---

    def float32(self, value: float) -> None:
        # NaN and the infinities are legal payloads; only the JSON codec rejects
        # them. A finite value too large for float32 is rejected rather than
        # saturated to an infinity, which is what Go's cast does.
        try:
            self._buf += _F32.pack(value)
        except OverflowError as exc:
            raise RangeError(f"float32: {value!r} out of range") from exc

    def float64(self, value: float) -> None:
        self._buf += _F64.pack(value)

    # --- single bytes ---

    def boolean(self, value: bool) -> None:
        self._buf += b"\x01" if value else b"\x00"

    def flag(self, present: bool) -> None:
        """A pointer nil flag or a container presence byte. Always 0x00 or 0x01.

        A present value is 0x01 in either position, which is byte-compatible with
        astral-go's reflection codec and with its blueprint-built containers.
        `codec.binary` owns the rule that decides `present`.
        """
        self._buf += b"\x01" if present else b"\x00"

    # --- length-prefixed ---

    def string8(self, value: str) -> None:
        self._prefixed("string8", 1, value.encode(_ENCODING, _ERRORS))

    def string16(self, value: str) -> None:
        self._prefixed("string16", 2, value.encode(_ENCODING, _ERRORS))

    def string32(self, value: str) -> None:
        self._prefixed("string32", 4, value.encode(_ENCODING, _ERRORS))

    def string64(self, value: str) -> None:
        self._prefixed("string64", 8, value.encode(_ENCODING, _ERRORS))

    def bytes8(self, value: bytes | bytearray | memoryview) -> None:
        self._prefixed("bytes8", 1, value)

    def bytes16(self, value: bytes | bytearray | memoryview) -> None:
        self._prefixed("bytes16", 2, value)

    def bytes32(self, value: bytes | bytearray | memoryview) -> None:
        self._prefixed("bytes32", 4, value)

    def bytes64(self, value: bytes | bytearray | memoryview) -> None:
        self._prefixed("bytes64", 8, value)

    def _prefixed(
        self, name: str, width: int, payload: bytes | bytearray | memoryview
    ) -> None:
        n = len(payload)
        if n > (1 << (8 * width)) - 1:
            raise ValueTooLarge(f"{name}: data too large")
        self._buf += n.to_bytes(width, "big")
        self._buf += payload
