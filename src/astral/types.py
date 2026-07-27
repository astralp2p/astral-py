"""The astral value types: Identity, Nonce, ObjectID, Time, Duration, Zone, Size.

All seven are frozen and hashable, and each carries four forms that must never
drift apart: the binary payload (`read`/`write`), the text form (`parse` /
`__str__`, except `Size`), the JSON form (`from_json` / `json`), and the Python
value itself.

Settled facts embedded here that must not be re-litigated:

- `identity` is 33 flat bytes on the wire. The presence byte belongs to the
  enclosing `Ptr("identity")` field, not to the value. Modelling it on the value
  is the single error that broke `dir.resolve`, `apphost.whoami`, `objects.find`
  and `user.list_siblings` over binary in the legacy SDK.
- The zero identity's JSON form is the literal `"anyone"`; its text form is 66
  zeros. The two differ for the same value.
- `zone` JSON is the string `"dvn"`, not a number. `Zone.parse` ignores
  unrecognised characters rather than raising, matching `astral.Zones`, and the
  empty string yields `Zone(0)` rather than the default.
- `nonce64` JSON is unpadded hex and its text form is padded to 16 digits.
- `time` is RFC 3339 in both JSON and text, with nanosecond precision.
- `Time` and `Duration` keep integer nanoseconds. `datetime` resolves only to
  microseconds, and dropping the low three digits changes every ObjectID over a
  time-bearing object.
- `str(Size)` is the human form `1.5KiB`, which is *not* the text encoding. The
  text encoding is the decimal byte count.

Each of the seven satisfies the `Object` protocol as well: `ASTRAL_TYPE` names
the wire type and `read_payload` / `write_payload` alias `read` / `write`. The
registry therefore holds the value type itself rather than a wrapper, so a
polymorphic field carrying an identity decodes to an `Identity` and compares
equal to one.
"""

from __future__ import annotations

import datetime as _dt
import enum
import re
import secrets
import time as _time
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from .errors import ParseError, RangeError
from .wire import Reader, Writer

__all__ = ["Duration", "Identity", "Nonce", "ObjectID", "Size", "Time", "Zone"]

_INT64_MIN: Final = -(1 << 63)
_INT64_MAX: Final = (1 << 63) - 1
_UINT64_MAX: Final = (1 << 64) - 1


# --- identity -------------------------------------------------------------

_ANYONE_KEY: Final = bytes(33)


@dataclass(frozen=True, slots=True, repr=False)
class Identity:
    """A compressed secp256k1 public key: 33 opaque bytes.

    The SDK never checks that the bytes are a point on the curve. astral-go's
    `Identity.ReadFrom` does, and we diverge deliberately: validation would make
    the wire core depend on a curve library for the most common decode in the
    protocol. Validation is opt-in through the `secp256k1` extra.
    """

    key: bytes = _ANYONE_KEY

    ASTRAL_TYPE: ClassVar[str] = "identity"
    SIZE: ClassVar[int] = 33
    ANYONE: ClassVar["Identity"]

    def __post_init__(self) -> None:
        key = self.key
        if not isinstance(key, bytes):
            object.__setattr__(self, "key", bytes(key))
            key = self.key
        if len(key) != self.SIZE:
            raise ParseError(f"identity: expected {self.SIZE} bytes, got {len(key)}")

    def __repr__(self) -> str:
        return f"Identity({'anyone' if self.is_zero else self.hex()})"

    def __str__(self) -> str:
        return self.hex()

    @property
    def is_zero(self) -> bool:
        return not any(self.key)

    def hex(self) -> str:
        return self.key.hex()

    def fingerprint(self) -> str:
        h = self.hex()
        return f"{h[:8]}:{h[-8:]}"

    @classmethod
    def parse(cls, text: str) -> "Identity":
        """Parse the text form: 66 hex characters, 66 zeros, or `anyone`."""
        if text == "anyone":
            return cls.ANYONE
        if len(text) != 66:
            raise ParseError(f"identity: expected 66 hex characters, got {len(text)}")
        try:
            return cls(bytes.fromhex(text))
        except ValueError as exc:
            raise ParseError(f"identity: {exc}") from exc

    def json(self) -> str:
        return "anyone" if self.is_zero else self.hex()

    @classmethod
    def from_json(cls, data: Any) -> "Identity":
        if data is None:
            return cls.ANYONE
        if not isinstance(data, str):
            raise ParseError(f"identity: expected a JSON string, got {type(data).__name__}")
        return cls.parse(data)

    def text(self) -> str:
        return self.hex()

    @classmethod
    def read(cls, r: Reader) -> "Identity":
        return cls(r.raw(cls.SIZE))

    def write(self, w: Writer) -> None:
        w.raw(self.key)

    read_payload = read
    write_payload = write


Identity.ANYONE = Identity(bytes(Identity.SIZE))


# --- nonce ----------------------------------------------------------------


class Nonce(int):
    """A 64-bit query correlator.

    An `int` subclass so arithmetic and dict keys keep working, with `__str__`
    fixed at 16 hex digits so log and CLI output is right by construction.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = "nonce64"

    def __new__(cls, value: int = 0) -> "Nonce":
        if not 0 <= value <= _UINT64_MAX:
            raise RangeError(f"nonce64: {value} out of range")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"Nonce({self!s})"

    def __str__(self) -> str:
        return f"{int(self):016x}"

    @classmethod
    def random(cls) -> "Nonce":
        return cls(secrets.randbits(64))

    @classmethod
    def parse(cls, text: str) -> "Nonce":
        """Parse hex, padded or unpadded. Both forms occur on the wire."""
        try:
            return cls(int(text, 16))
        except ValueError as exc:
            raise ParseError(f"nonce64: {text!r} is not hex") from exc

    def json(self) -> str:
        # Unpadded, bug-compatible with astral-go's strconv.FormatUint(u, 16).
        # The docs claim 16 digits; the node emits leading zeros stripped.
        return format(int(self), "x")

    @classmethod
    def from_json(cls, data: Any) -> "Nonce":
        if not isinstance(data, str):
            raise ParseError(f"nonce64: expected a JSON string, got {type(data).__name__}")
        return cls.parse(data)

    def text(self) -> str:
        return str(self)

    @classmethod
    def read(cls, r: Reader) -> "Nonce":
        return cls(r.uint64())

    def write(self, w: Writer) -> None:
        w.uint64(int(self))

    read_payload = read
    write_payload = write


# --- zone -----------------------------------------------------------------


class Zone(enum.IntFlag):
    """The routing zones a query may traverse: device, virtual, network."""

    # An enum body turns a bare assignment into a member, so the type name is
    # marked a non-member explicitly.
    ASTRAL_TYPE = enum.nonmember("zone")

    NONE = 0
    DEVICE = 1
    VIRTUAL = 2
    NETWORK = 4
    D = 1
    V = 2
    N = 4
    ALL = 7

    def __str__(self) -> str:
        s = ""
        if self & Zone.DEVICE:
            s += "d"
        if self & Zone.VIRTUAL:
            s += "v"
        if self & Zone.NETWORK:
            s += "n"
        return s

    def __repr__(self) -> str:
        return f"Zone({str(self)!r})"

    @classmethod
    def parse(cls, text: str) -> "Zone":
        """OR the recognised letters, ignoring everything else.

        Unrecognised characters are silently dropped, matching `astral.Zones`,
        and the empty string yields `Zone(0)` -- not the default. The legacy SDK
        raised here, which is stricter than the protocol.
        """
        zone = 0
        for c in text:
            if c == "d":
                zone |= 1
            elif c == "v":
                zone |= 2
            elif c == "n":
                zone |= 4
        return cls(zone)

    def json(self) -> str:
        return str(self)

    @classmethod
    def from_json(cls, data: Any) -> "Zone":
        if not isinstance(data, str):
            raise ParseError(f"zone: expected a JSON string, got {type(data).__name__}")
        return cls.parse(data)

    def text(self) -> str:
        return str(self)

    @classmethod
    def read(cls, r: Reader) -> "Zone":
        return cls(r.uint8())

    def write(self, w: Writer) -> None:
        w.uint8(int(self))

    read_payload = read
    write_payload = write

    @classmethod
    def ASTRAL_ZERO(cls) -> "Zone":  # noqa: N802 -- the registry's zero-value hook
        """`Zone(0)`.

        An enum class is not callable with no argument, so the registry cannot
        construct the zero value the way it does for every other type.
        """
        return cls(0)


# --- size -----------------------------------------------------------------

_SIZE_UNITS: Final = (
    ("EiB", 1 << 60),
    ("PiB", 1 << 50),
    ("TiB", 1 << 40),
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
)

_SIZE_SUFFIX: Final = {"k": 1, "m": 2, "g": 3, "t": 4, "p": 5, "e": 6}


class Size(int):
    """A byte count.

    `str(Size)` is the human binary form and `Size.text()` is the decimal wire
    form. They are two different strings for the same value and confusing them
    sends `1.5KiB` where a number belongs.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = "size"

    def __new__(cls, value: int = 0) -> "Size":
        if not 0 <= value <= _UINT64_MAX:
            raise RangeError(f"size: {value} out of range")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"Size({int(self)})"

    def __str__(self) -> str:
        v = int(self)
        for suffix, unit in _SIZE_UNITS:
            # Strictly greater than, matching astral-go: 1024 renders as "1024B".
            if v > unit:
                return f"{v / unit:.1f}{suffix}"
        return f"{v}B"

    @classmethod
    def parse(cls, text: str) -> "Size":
        """Parse the decimal wire form, or a suffixed form such as `1.5MB`.

        The wire text encoding is decimal. The suffixed form exists because some
        ops take a size string as a query-string parameter.
        """
        s = text.strip().lower()
        if not s:
            raise ParseError("size: empty string")
        multiplier = 1000
        if s.endswith("ib"):
            multiplier, s = 1024, s[:-2]
        elif s.endswith("b"):
            s = s[:-1]
        scale = 1
        if s and s[-1] in _SIZE_SUFFIX:
            scale = multiplier ** _SIZE_SUFFIX[s[-1]]
            s = s[:-1]
        try:
            f = float(s.strip())
        except ValueError as exc:
            raise ParseError(f"size: {text!r} is not a size") from exc
        if f < 0:
            raise ParseError(f"size: {text!r} is negative")
        value = int(f * scale)
        if value / scale != f:
            raise ParseError(f"size: {text!r} overflows or loses precision")
        return cls(value)

    def json(self) -> int:
        return int(self)

    @classmethod
    def from_json(cls, data: Any) -> "Size":
        if not isinstance(data, int) or isinstance(data, bool):
            raise ParseError(f"size: expected a JSON number, got {type(data).__name__}")
        return cls(data)

    def text(self) -> str:
        return str(int(self))

    @classmethod
    def read(cls, r: Reader) -> "Size":
        return cls(r.uint64())

    def write(self, w: Writer) -> None:
        w.uint64(int(self))

    read_payload = read
    write_payload = write


# --- time -----------------------------------------------------------------

_RFC3339: Final = re.compile(
    r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[Tt]"
    r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?:[Zz]|(?P<sign>[+-])(?P<oh>\d{2}):(?P<om>\d{2}))$"
)

_EPOCH_ORDINAL: Final = _dt.date(1970, 1, 1).toordinal()
_EPOCH: Final = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


class Time(int):
    """An instant, as integer nanoseconds since the Unix epoch.

    Nanoseconds are the canonical value. `.datetime` is a lossy convenience:
    `datetime` resolves only to microseconds, and a round trip through it moves
    every ObjectID computed over the object.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = "time"

    def __new__(cls, nanos: int = 0) -> "Time":
        if not _INT64_MIN <= nanos <= _INT64_MAX:
            raise RangeError(f"time: {nanos} nanoseconds out of int64 range")
        return super().__new__(cls, nanos)

    def __repr__(self) -> str:
        return f"Time({self!s})"

    def __str__(self) -> str:
        secs, frac = divmod(int(self), 1_000_000_000)
        d = _EPOCH + _dt.timedelta(seconds=secs)
        out = (
            f"{d.year:04d}-{d.month:02d}-{d.day:02d}T"
            f"{d.hour:02d}:{d.minute:02d}:{d.second:02d}"
        )
        if frac:
            out += "." + f"{frac:09d}".rstrip("0")
        return out + "Z"

    @property
    def nanos(self) -> int:
        return int(self)

    @property
    def datetime(self) -> _dt.datetime:
        """Lossy: truncates to microseconds."""
        return _EPOCH + _dt.timedelta(microseconds=int(self) // 1000)

    @classmethod
    def now(cls) -> "Time":
        # time_ns, not datetime.timestamp(): a float seconds count cannot carry
        # nanoseconds at present-day magnitudes.
        return cls(_time.time_ns())

    @classmethod
    def from_datetime(cls, value: _dt.datetime) -> "Time":
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.timezone.utc)
        delta = value - _EPOCH
        return cls(
            (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
        )

    @classmethod
    def parse(cls, text: str) -> "Time":
        """Parse RFC 3339. The docs say ISO 8601; the implementation is RFC 3339 only."""
        m = _RFC3339.match(text)
        if m is None:
            raise ParseError(f"time: {text!r} is not RFC 3339")
        frac = m.group("frac") or ""
        if len(frac) > 9:
            raise ParseError(f"time: {text!r} has more than nanosecond precision")
        try:
            days = _dt.date(int(m.group("y")), int(m.group("mo")), int(m.group("d")))
        except ValueError as exc:
            raise ParseError(f"time: {text!r}: {exc}") from exc
        secs = (days.toordinal() - _EPOCH_ORDINAL) * 86400
        secs += int(m.group("h")) * 3600 + int(m.group("mi")) * 60 + int(m.group("s"))
        if m.group("sign"):
            offset = int(m.group("oh")) * 3600 + int(m.group("om")) * 60
            secs -= offset if m.group("sign") == "+" else -offset
        return cls(secs * 1_000_000_000 + int(frac.ljust(9, "0") or "0"))

    def json(self) -> str:
        return str(self)

    @classmethod
    def from_json(cls, data: Any) -> "Time":
        if not isinstance(data, str):
            raise ParseError(f"time: expected a JSON string, got {type(data).__name__}")
        return cls.parse(data)

    def text(self) -> str:
        return str(self)

    @classmethod
    def read(cls, r: Reader) -> "Time":
        # Written as uint64(int64 nanoseconds): pre-epoch instants wrap through
        # the unsigned range, and the cast is lossless in both directions.
        v = r.uint64()
        return cls(v - (1 << 64) if v > _INT64_MAX else v)

    def write(self, w: Writer) -> None:
        w.uint64(int(self) & _UINT64_MAX)

    read_payload = read
    write_payload = write


# --- duration -------------------------------------------------------------

_DURATION_UNITS: Final = {
    "ns": 1,
    "us": 1_000,
    "µs": 1_000,  # U+00B5 micro sign, what Go emits
    "μs": 1_000,  # U+03BC greek small mu, accepted on parse
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60 * 1_000_000_000,
    "h": 3600 * 1_000_000_000,
}

_DIGITS: Final = "0123456789"


def _fmt_frac(v: int, prec: int) -> tuple[str, int]:
    """Render the fraction of `v / 10**prec`, then return it and the quotient.

    Trailing zeros are dropped and the point disappears with them, which is what
    makes Go's duration strings `1m30s` rather than `1m30.000000000s`.
    """
    out: list[str] = []
    printing = False
    for _ in range(prec):
        digit = v % 10
        printing = printing or digit != 0
        if printing:
            out.append(chr(48 + digit))
        v //= 10
    if printing:
        out.append(".")
    return "".join(reversed(out)), v


class Duration(int):
    """A span, as signed integer nanoseconds.

    The wire form is a signed int64, the JSON form is that integer, and the text
    form is Go's duration string.
    """

    __slots__ = ()

    ASTRAL_TYPE: ClassVar[str] = "duration"

    def __new__(cls, nanos: int = 0) -> "Duration":
        if not _INT64_MIN <= nanos <= _INT64_MAX:
            raise RangeError(f"duration: {nanos} nanoseconds out of int64 range")
        return super().__new__(cls, nanos)

    def __repr__(self) -> str:
        return f"Duration({self!s})"

    def __str__(self) -> str:
        d = int(self)
        if d == 0:
            return "0s"
        u = -d if d < 0 else d
        if u < 1_000_000_000:
            if u < 1_000:
                prec, unit = 0, "ns"
            elif u < 1_000_000:
                prec, unit = 3, "µs"
            else:
                prec, unit = 6, "ms"
            frac, u = _fmt_frac(u, prec)
            out = f"{u}{frac}{unit}"
        else:
            frac, u = _fmt_frac(u, 9)
            out = f"{u % 60}{frac}s"
            u //= 60
            if u > 0:
                out = f"{u % 60}m{out}"
                u //= 60
                if u > 0:
                    out = f"{u}h{out}"
        return ("-" if d < 0 else "") + out

    @property
    def nanos(self) -> int:
        return int(self)

    @property
    def timedelta(self) -> _dt.timedelta:
        """Lossy: truncates to microseconds."""
        return _dt.timedelta(microseconds=int(self) // 1000)

    @classmethod
    def parse(cls, text: str) -> "Duration":
        """Parse a Go duration string: a signed run of `<number><unit>` pairs."""
        s = text
        neg = False
        if s[:1] in ("-", "+"):
            neg = s[0] == "-"
            s = s[1:]
        if s == "0":
            return cls(0)
        if not s:
            raise ParseError(f"duration: {text!r} is empty")
        total = 0
        i = 0
        while i < len(s):
            start = i
            while i < len(s) and s[i] in _DIGITS:
                i += 1
            int_part = s[start:i]
            frac_part = ""
            if i < len(s) and s[i] == ".":
                i += 1
                start = i
                while i < len(s) and s[i] in _DIGITS:
                    i += 1
                frac_part = s[start:i]
            if not int_part and not frac_part:
                raise ParseError(f"duration: {text!r} has no number")
            start = i
            while i < len(s) and s[i] not in _DIGITS and s[i] != ".":
                i += 1
            unit = s[start:i]
            scale = _DURATION_UNITS.get(unit)
            if scale is None:
                raise ParseError(f"duration: unknown unit {unit!r} in {text!r}")
            total += int(int_part or "0") * scale
            if frac_part:
                total += int(frac_part) * scale // 10 ** len(frac_part)
        return cls(-total if neg else total)

    def json(self) -> int:
        return int(self)

    @classmethod
    def from_json(cls, data: Any) -> "Duration":
        if not isinstance(data, int) or isinstance(data, bool):
            raise ParseError(f"duration: expected a JSON number, got {type(data).__name__}")
        return cls(data)

    def text(self) -> str:
        return str(self)

    @classmethod
    def read(cls, r: Reader) -> "Duration":
        return cls(r.int64())

    def write(self, w: Writer) -> None:
        w.int64(int(self))

    read_payload = read
    write_payload = write


# --- object id ------------------------------------------------------------

_ZBASE32: Final = "ybndrfg8ejkmcpqxot1uwisza345h769"
_ZBASE32_INDEX: Final = {c: i for i, c in enumerate(_ZBASE32)}
_ID_PREFIX: Final = "data1"
_ID_SYMBOLS: Final = 64  # 40 bytes = 320 bits = exactly 64 symbols, never padded


def _zbase32_encode(data: bytes) -> str:
    v = int.from_bytes(data, "big")
    out = [""] * _ID_SYMBOLS
    for i in range(_ID_SYMBOLS - 1, -1, -1):
        out[i] = _ZBASE32[v & 31]
        v >>= 5
    return "".join(out)


def _zbase32_decode(symbols: str) -> bytes:
    v = 0
    for c in symbols:
        index = _ZBASE32_INDEX.get(c)
        if index is None:
            raise ParseError(f"object_id: {c!r} is not a zBase32 symbol")
        v = (v << 5) | index
    return v.to_bytes(40, "big")


@dataclass(frozen=True, slots=True, repr=False)
class ObjectID:
    """A content address: the object's byte length and the SHA-256 of its bytes."""

    size: int = 0
    hash: bytes = bytes(32)

    ASTRAL_TYPE: ClassVar[str] = "object_id.sha256"
    ZERO: ClassVar["ObjectID"]

    def __post_init__(self) -> None:
        if not isinstance(self.hash, bytes):
            object.__setattr__(self, "hash", bytes(self.hash))
        if len(self.hash) != 32:
            raise ParseError(f"object_id: expected a 32-byte hash, got {len(self.hash)}")
        if not 0 <= self.size <= _UINT64_MAX:
            raise RangeError(f"object_id: size {self.size} out of range")

    def __repr__(self) -> str:
        return f"ObjectID({str(self)!r})"

    def __str__(self) -> str:
        b = self.size.to_bytes(8, "big") + self.hash
        # Leading `y` symbols are stripped. The primitive-type doc omits this;
        # omitting it produces a 69-character ID and every comparison fails.
        return _ID_PREFIX + _zbase32_encode(b).lstrip(_ZBASE32[0])

    @property
    def is_zero(self) -> bool:
        # The hash alone decides, matching astral-go. {Size: 99, Hash: 0} is
        # therefore "zero" and its Size is dropped on the wire.
        return not any(self.hash)

    @classmethod
    def parse(cls, text: str) -> "ObjectID":
        if not text.startswith(_ID_PREFIX):
            raise ParseError(f"object_id: {text!r} has no {_ID_PREFIX!r} prefix")
        body = text[len(_ID_PREFIX) :]
        if len(body) > _ID_SYMBOLS:
            raise ParseError(f"object_id: {text!r} is too long")
        data = _zbase32_decode(body.rjust(_ID_SYMBOLS, _ZBASE32[0]))
        return cls(size=int.from_bytes(data[:8], "big"), hash=data[8:])

    def json(self) -> str:
        return "" if self.is_zero else str(self)

    @classmethod
    def from_json(cls, data: Any) -> "ObjectID":
        # astral-go marshals the zero ID to "" and then cannot parse "" back. We
        # emit "" for bug-compatibility and accept it, declining the asymmetry.
        if data is None or data == "":
            return cls.ZERO
        if not isinstance(data, str):
            raise ParseError(f"object_id: expected a JSON string, got {type(data).__name__}")
        return cls.parse(data)

    def text(self) -> str:
        return str(self)

    @classmethod
    def read(cls, r: Reader) -> "ObjectID":
        return cls(size=r.uint64(), hash=r.raw(32))

    def write(self, w: Writer) -> None:
        if self.is_zero:
            w.raw(bytes(40))
            return
        w.uint64(self.size)
        w.raw(self.hash)

    read_payload = read
    write_payload = write


ObjectID.ZERO = ObjectID()
