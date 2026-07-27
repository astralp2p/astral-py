"""Query strings: the operation name, its parameters, and the encoding between.

    dir.resolve?name=furry-bolt
    objects.read?id=data19kyg…&zone=dvn

Rules that are not negotiable, every one of them observed on the live node:

- **Parameter values are the bare payload half of the text encoding.** No
  `#[type]` header ever appears in a query string: the parameter's type comes
  from the operation's declaration, so it does not travel. `encode_param` is the
  single implementation and it delegates to `codec.text`.
- **Keys are sorted**, matching Go's `url.Values.Encode()`, so a query string is
  reproducible byte for byte against the reference client.
- **Escaping is Go's `url.QueryEscape`**: unreserved is `A-Za-z0-9-_.~`, a space
  becomes `+`, everything else becomes `%XX`. Python's `quote_plus` with no safe
  characters is exactly that set.
- **Key matching on the node is case-sensitive and an unknown key is silently
  dropped.** A capitalised key therefore does nothing at all -- no error, no
  effect -- which is why astral-go's own `apphost.new_app_contract` sending `ID`
  and `Duration` is a no-op bug. Send lowercase always.
- **`arg` is reserved** for the positional argument: a CLI token with no `-key`
  in front of it lands there, and a later positional overwrites an earlier one.
- **The 255-byte cap is advice, not a wire limit.** `route_query_msg.Query` is a
  `string16`, so anything up to 65 535 bytes reaches the node. Above 255 bytes
  this module warns; above 65 535 it refuses. The legacy SDK hard-capped at 255
  and rejected legitimate queries client-side.
- **A parameter the caller did not set is omitted, never sent empty.** An empty
  string is a legitimate `string8`, so `key=` and an absent key are different
  things, and defaults such as the signature scheme only hold while the key stays
  absent.
"""

from __future__ import annotations

import urllib.parse
import warnings
from typing import Any as AnyValue
from typing import Final, Mapping, Sequence

from .codec.jsoncodec import encode_base64, float_text
from .codec.text import read_text_spec, text_spec, to_text
from .codec.text import decode as decode_text
from .errors import ValueTooLarge
from .registry import Blueprints
from .spec import Spec

__all__ = [
    "ADVISORY_LENGTH",
    "ARG_KEY",
    "MAX_LENGTH",
    "QueryStringTooLong",
    "args_to_params",
    "bare_param",
    "build",
    "encode_param",
    "encode_params",
    "parse",
    "parse_param",
    "param_text",
    "quote",
    "unquote",
]

# The map key a positional argument occupies. astral-go's `query.DefaultArgKey`.
ARG_KEY: Final = "arg"

# The documented policy limit, and the wire limit of the string16 that carries it.
ADVISORY_LENGTH: Final = 255
MAX_LENGTH: Final = 65535

_HEADER_OPEN: Final = "#["


class QueryStringTooLong(UserWarning):
    """A query string passed the documented 255-byte policy limit.

    A warning and not an error: the field on the wire is a `string16` and the
    node accepts what fits it.
    """


def quote(value: str) -> str:
    """Escape one key or value exactly as Go's `url.QueryEscape` does."""
    return urllib.parse.quote_plus(value, safe="", encoding="utf-8", errors="surrogateescape")


def unquote(value: str) -> str:
    """Reverse `quote`.

    Unlike Go, a malformed escape is left as written rather than discarding the
    whole query string: astral-go's `query.Parse` throws away every parameter
    when `url.ParseQuery` reports one bad escape, which turns a typo into a
    silently parameterless call.
    """
    return urllib.parse.unquote_plus(value, encoding="utf-8", errors="surrogateescape")


def param_text(value: AnyValue) -> str:
    """The bare text form of a parameter whose spec the caller did not name.

    Resolution order matters: every astral value type is an `int` subclass, so
    the type's own text form has to win over the integer branch. `Size` is the
    case that proves it -- `str(Size(1536))` is the human form `1.5KiB` and its
    text encoding is `1536`.
    """
    if isinstance(value, str):
        return value
    own = getattr(value, "text", None)
    if callable(own):
        return own()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (bytes, bytearray, memoryview)):
        return encode_base64(bytes(value))
    if isinstance(value, int):
        return str(int(value))
    if isinstance(value, float):
        return float_text(value)
    return str(value)


def encode_param(spec: Spec, value: AnyValue) -> str:
    """One parameter's value, in the bare half of its type's text encoding."""
    return text_spec(spec, value)


def parse_param(
    spec: Spec, text: str, *, registry: Blueprints | None = None
) -> AnyValue:
    """One parameter's value, from the bare half of its type's text encoding."""
    return read_text_spec(spec, text, registry=registry)


def encode_params(
    specs: Mapping[str, Spec], values: Mapping[str, AnyValue]
) -> dict[str, str]:
    """Encode declared parameters, dropping the ones the caller left unset.

    A key with no declared spec falls through to `param_text`, so a hand-written
    parameter still reaches the node.
    """
    out: dict[str, str] = {}
    for key, value in values.items():
        if value is None:
            continue
        spec = specs.get(key)
        out[key] = encode_param(spec, value) if spec is not None else param_text(value)
    return out


def build(
    op: str,
    params: Mapping[str, AnyValue] | None = None,
    /,
    **kw: AnyValue,
) -> str:
    """`op` alone, or `op?k=v&…` with the keys sorted and every value escaped.

    `params` is positional-only so a parameter may be named anything at all,
    including the names this function's own signature uses.
    """
    merged: dict[str, AnyValue] = dict(params or {})
    merged.update(kw)

    pairs = [
        f"{quote(key)}={quote(param_text(value))}"
        for key, value in sorted(merged.items())
        if value is not None
    ]
    query = (op + "?" + "&".join(pairs)) if pairs else op

    size = len(query.encode("utf-8", "surrogateescape"))
    if size > MAX_LENGTH:
        raise ValueTooLarge(f"query string: {size} bytes exceeds {MAX_LENGTH}")
    if size > ADVISORY_LENGTH:
        warnings.warn(
            f"query string: {size} bytes passes the documented {ADVISORY_LENGTH}-byte limit",
            QueryStringTooLong,
            stacklevel=2,
        )
    return query


def parse(query: str) -> tuple[str, dict[str, str]]:
    """Split a query string into its operation name and its parameters.

    The first value of a repeated key wins, matching astral-go, which keeps
    `url.Values[k][0]`. A segment with no `=` yields an empty value under that
    key: astral-go's `query.Parse` has a branch meant to route it to `arg`
    instead, but `url.ParseQuery` always produces a value, so the branch is dead
    and the empty value is what the node actually sees.
    """
    op, separator, rest = query.partition("?")
    params: dict[str, str] = {}
    if not separator:
        return op, params
    for segment in rest.split("&"):
        if not segment:
            continue
        key, _, raw = segment.partition("=")
        name = unquote(key)
        if name not in params:
            params[name] = unquote(raw)
    return op, params


def args_to_params(args: Sequence[str]) -> dict[str, str]:
    """Turn a `-key value` CLI argument list into parameters.

    A token with no leading dash is positional and lands under `arg`. One or two
    leading dashes are both stripped, so `-zone` and `--zone` name the same
    parameter. A trailing `-key` with no value sets that key empty, which is what
    astral-go's `ArgsToMap` does.

    astral-go's other reader of the same shape, `query.Editor.SetArgs`, never
    advances its index past a positional token and spins forever; that one is a
    bug, not a behaviour to reproduce.
    """
    params: dict[str, str] = {}
    index = 0
    while index < len(args):
        token = args[index]
        if not token.startswith("-"):
            params[ARG_KEY] = token
            index += 1
            continue
        key = token[2:] if token.startswith("--") else token[1:]
        if index + 1 >= len(args):
            params[key] = ""
            return params
        params[key] = args[index + 1]
        index += 2
    return params


def bare_param(text: str, *, registry: Blueprints | None = None) -> str:
    """Reduce a possibly type-tagged CLI value to the bare parameter form.

    `-p name=#[uint8] 21` lets a caller spell a parameter's type explicitly; the
    query string carries only the payload half, so the tagged form is decoded and
    re-rendered. A value with no `#[` header passes through untouched.
    """
    if not text.startswith(_HEADER_OPEN):
        return text
    return to_text(decode_text(text, registry=registry))
