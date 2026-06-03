"""apphost IPC control messages and their binary/JSON codecs.

These are the ``mod.apphost.*`` objects exchanged during the session handshake
and query setup (``topics/astral-ipc.md``, ``topics/ws-transport.md``).

Each message is a small dataclass whose ``FIELDS`` schema drives serialization
in both directions. Field values are stored in their friendly Python form
(identities and nonces as hex strings, zones as letter strings); the codecs
translate to/from binary and JSON.

Note: the binary field layouts follow the documented field lists and the
common-type encodings. Where the docs are silent on exact widths (notably the
single-byte ``zone`` mask and the fixed 33-byte identity), this module makes
the documented assumptions described in :mod:`astral.codec`. The JSON transports
(HTTP/WebSocket) are unaffected by those assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, ClassVar, Dict, List, Tuple, Type

from .codec import BinaryReader, BinaryWriter
from .encoding import Zone
from .errors import ProtocolError
from .objects import AstralObject

__all__ = [
    "Message",
    "REGISTRY",
    "message_from_object",
    "HostInfoMsg",
    "AuthTokenMsg",
    "AuthSuccessMsg",
    "ErrorMsg",
    "RouteQueryMsg",
    "QueryAcceptedMsg",
    "QueryRejectedMsg",
    "RegisterServiceMsg",
    "IncomingQueryMsg",
    "AttachQueryMsg",
    "RejectIncomingMsg",
    "HandleQueryMsg",
    "BindMsg",
]

# (field_name, kind) schema entries use these kind tags.
_KIND_IDENTITY = "identity"
_KIND_STRING8 = "string8"
_KIND_STRING16 = "string16"
_KIND_NONCE = "nonce64"
_KIND_UINT8 = "uint8"
_KIND_ZONE = "zone"
_KIND_STR_ARRAY = "[]string8"


def _write_field(writer: BinaryWriter, kind: str, value: Any) -> None:
    if kind == _KIND_IDENTITY:
        writer.identity(value or "")
    elif kind == _KIND_STRING8:
        writer.string8(value or "")
    elif kind == _KIND_STRING16:
        writer.string16(value or "")
    elif kind == _KIND_NONCE:
        writer.nonce(value)
    elif kind == _KIND_UINT8:
        writer.u8(int(value))
    elif kind == _KIND_ZONE:
        writer.u8(Zone.to_mask(value))
    elif kind == _KIND_STR_ARRAY:
        items = value or []
        writer.u32(len(items))
        for item in items:
            writer.string8(item)
    else:  # pragma: no cover - guarded by construction
        raise ProtocolError(f"unknown field kind: {kind}")


def _read_field(reader: BinaryReader, kind: str) -> Any:
    if kind == _KIND_IDENTITY:
        return reader.identity()
    if kind == _KIND_STRING8:
        return reader.string8()
    if kind == _KIND_STRING16:
        return reader.string16()
    if kind == _KIND_NONCE:
        return reader.nonce()
    if kind == _KIND_UINT8:
        return reader.u8()
    if kind == _KIND_ZONE:
        return Zone.to_string(reader.u8())
    if kind == _KIND_STR_ARRAY:
        return [reader.string8() for _ in range(reader.u32())]
    raise ProtocolError(f"unknown field kind: {kind}")  # pragma: no cover


def _field_to_json(kind: str, value: Any) -> Any:
    if kind == _KIND_ZONE:
        return Zone.to_string(value)
    if kind == _KIND_STR_ARRAY:
        return list(value or [])
    return value


def _field_from_json(kind: str, value: Any) -> Any:
    if kind == _KIND_ZONE:
        return Zone.to_string(value if value is not None else Zone.ALL)
    if kind == _KIND_STR_ARRAY:
        return list(value or [])
    if kind in (_KIND_IDENTITY, _KIND_STRING8, _KIND_STRING16, _KIND_NONCE):
        return value if value is not None else ""
    if kind == _KIND_UINT8:
        return int(value) if value is not None else 0
    return value


REGISTRY: Dict[str, Type["Message"]] = {}


@dataclass
class Message:
    """Base class for apphost control messages."""

    TYPE: ClassVar[str] = ""
    FIELDS: ClassVar[Tuple[Tuple[str, str], ...]] = ()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.TYPE:
            REGISTRY[cls.TYPE] = cls

    # -- binary -------------------------------------------------------------
    def encode_binary(self) -> bytes:
        writer = BinaryWriter()
        for name, kind in self.FIELDS:
            _write_field(writer, kind, getattr(self, name))
        return writer.getvalue()

    @classmethod
    def decode_binary(cls, payload: bytes) -> "Message":
        reader = BinaryReader(payload)
        values = {name: _read_field(reader, kind) for name, kind in cls.FIELDS}
        return cls(**values)

    # -- JSON ---------------------------------------------------------------
    def encode_json(self) -> Any:
        if not self.FIELDS:
            return None
        return {name: _field_to_json(kind, getattr(self, name)) for name, kind in self.FIELDS}

    @classmethod
    def decode_json(cls, value: Any) -> "Message":
        value = value or {}
        return cls(**{name: _field_from_json(kind, value.get(name)) for name, kind in cls.FIELDS})

    # -- object bridge ------------------------------------------------------
    def to_object(self) -> AstralObject:
        """Wrap this message as an :class:`AstralObject` (JSON value form)."""
        return AstralObject(self.TYPE, self.encode_json())

    def __repr__(self) -> str:
        parts = ", ".join(f"{f.name}={getattr(self, f.name)!r}" for f in fields(self))
        return f"{type(self).__name__}({parts})"


def message_from_object(obj: AstralObject) -> Message:
    """Decode a known apphost message from a JSON-form :class:`AstralObject`."""
    cls = REGISTRY.get(obj.type)
    if cls is None:
        raise ProtocolError(f"unexpected message type: {obj.type!r}")
    return cls.decode_json(obj.value)


# --- handshake --------------------------------------------------------------


@dataclass
class HostInfoMsg(Message):
    TYPE = "mod.apphost.host_info_msg"
    FIELDS = (("Identity", _KIND_IDENTITY), ("Alias", _KIND_STRING8))
    Identity: str = ""
    Alias: str = ""


@dataclass
class AuthTokenMsg(Message):
    TYPE = "mod.apphost.auth_token_msg"
    FIELDS = (("Token", _KIND_STRING8),)
    Token: str = ""


@dataclass
class AuthSuccessMsg(Message):
    TYPE = "mod.apphost.auth_success_msg"
    FIELDS = (("GuestID", _KIND_IDENTITY),)
    GuestID: str = ""


@dataclass
class ErrorMsg(Message):
    TYPE = "mod.apphost.error_msg"
    FIELDS = (("Code", _KIND_STRING8),)
    Code: str = ""


# --- outbound queries -------------------------------------------------------


@dataclass
class RouteQueryMsg(Message):
    TYPE = "mod.apphost.route_query_msg"
    FIELDS = (
        ("Nonce", _KIND_NONCE),
        ("Caller", _KIND_IDENTITY),
        ("Target", _KIND_IDENTITY),
        ("Query", _KIND_STRING16),
        ("Zone", _KIND_ZONE),
        ("Filters", _KIND_STR_ARRAY),
    )
    Nonce: str = ""
    Caller: str = ""
    Target: str = ""
    Query: str = ""
    Zone: str = Zone.DEFAULT
    Filters: List[str] = field(default_factory=list)


@dataclass
class QueryAcceptedMsg(Message):
    TYPE = "mod.apphost.query_accepted_msg"
    FIELDS = ()


@dataclass
class QueryRejectedMsg(Message):
    TYPE = "mod.apphost.query_rejected_msg"
    FIELDS = (("Code", _KIND_UINT8),)
    Code: int = 1


# --- inbound queries (register-service) -------------------------------------


@dataclass
class RegisterServiceMsg(Message):
    TYPE = "mod.apphost.register_service_msg"
    FIELDS = (("Identity", _KIND_IDENTITY),)
    Identity: str = ""


@dataclass
class IncomingQueryMsg(Message):
    TYPE = "mod.apphost.incoming_query_msg"
    FIELDS = (
        ("QueryID", _KIND_NONCE),
        ("Caller", _KIND_IDENTITY),
        ("Target", _KIND_IDENTITY),
        ("Query", _KIND_STRING16),
    )
    QueryID: str = ""
    Caller: str = ""
    Target: str = ""
    Query: str = ""


@dataclass
class AttachQueryMsg(Message):
    TYPE = "mod.apphost.attach_query_msg"
    FIELDS = (("QueryID", _KIND_NONCE),)
    QueryID: str = ""


@dataclass
class RejectIncomingMsg(Message):
    TYPE = "mod.apphost.reject_incoming_msg"
    FIELDS = (("QueryID", _KIND_NONCE), ("Code", _KIND_UINT8))
    QueryID: str = ""
    Code: int = 1


# --- inbound queries (register-handler) -------------------------------------


@dataclass
class HandleQueryMsg(Message):
    TYPE = "mod.apphost.handle_query_msg"
    FIELDS = (
        ("IpcToken", _KIND_NONCE),
        ("ID", _KIND_NONCE),
        ("Caller", _KIND_IDENTITY),
        ("Target", _KIND_IDENTITY),
        ("Query", _KIND_STRING16),
    )
    IpcToken: str = ""
    ID: str = ""
    Caller: str = ""
    Target: str = ""
    Query: str = ""


@dataclass
class BindMsg(Message):
    TYPE = "mod.apphost.bind_msg"
    FIELDS = (("Token", _KIND_NONCE),)
    Token: str = ""
