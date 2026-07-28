"""The text channel and its two output-only variants.

One framing, three output spellings, one input parser:

| Format | Direction | Line |
|---|---|---|
| `text` | in and out | `#[type] <the type's text form>` or `#[type]:<base64>` |
| `base64` | out only | `#[type]:<base64>`, always, even where a text form exists |
| `render` | out only | the object's human rendering, with no header at all |

The encoding is `codec.text`'s and nothing here re-derives it. What the node
writes, verified against `furry-bolt` this session:

```
apphost.whoami?out=text     #[identity] 03b27049…ae1
apphost.whoami?out=base64   #[identity]:A7JwSUi7LkYDzLG81fAfXfmqUsv5S2tUo5eN+BGFvXrh
dir.alias_map?out=text      #[mod.dir.alias_map]:AAAAAQAKZnVycnktYm9sdAED…
dir.filters?out=text        five `#[string8] …` lines, then `#[eos] `
```

A record has no text form, so it takes the base64 branch on a `text` channel;
that is the emitter's rule, not the parser's, and `codec.text` documents both.
`eos` is an ordinary object here as well: `#[eos] ` is a header, a separator and
an empty body.

**`render` is display, never data.** Two facts settle it, both verified against
the live node rather than argued:

- The node's render sender resolves each object through a **view registry** it
  holds (`astral/fmt`'s `SetView`), so `apphost.whoami?out=render` answers
  `\\x1b[38;2;255;162;68mfurry-bolt\\x1b[0m` -- an alias, in colour, where the
  object is an identity, and `objects.repositories?out=render` answers
  `local: Local storage (8.6GiB free)`. No client can reproduce that: the views
  and the palette live in astrald.
- There is no render receiver anywhere. astral-go's `newReceiver` has no
  `render` case, so `in=render` is "unsupported input format".

`render()` here is astral-go's `Stringify` in Python terms -- the object's own
text form when it has one, `str(obj)` otherwise -- which is what a node with no
view installed emits. It is not byte-compatible with astrald's output and cannot
be, and nothing parses it back.

An `UnparsedObject` is refused by the text channel, where astral-go's text
sender would emit its base64 form: `UnparsedObject.text()` raises `ParseError`,
which `codec.text.encode` does not catch, so no base64 fallback is reached.
Layer 1 owns that decision and it is left standing.
"""

from __future__ import annotations

from typing import Any, ClassVar, Mapping

from ..codec import text as textcodec
from ..errors import ParseError, SchemaError
from ..registry import Blueprints
from ..transport import Transport
from ..wire import DEFAULT_MAX_ALLOC
from . import TEXT_OUTPUT_FORMATS, Format, parse_format
from .lines import LineChannel

__all__ = ["TextChannel", "render", "render_line"]


def render(obj: Any) -> str:
    """One object's human rendering, with no type header.

    The type's own text form when it has one, `str(obj)` otherwise. astral-go's
    `Stringify` orders those two the other way -- `String()`, then
    `MarshalText()`, then `%v` -- and the order cannot be ported, because
    Python's `__str__` is a `repr` fallback rather than a declared marshaller:
    preferring it would render `uint32(42)` as `Uint32(42)` and a blob as
    `b'raw'`. Among registered types the two orders differ on `size` alone,
    where astral-go's `Size.String()` is the human `1.5KiB` and the text form is
    the decimal `1536`.

    A record has neither a text form nor a Go `String()`, so astral-go prints a
    struct dump (`&{map[furry-bolt:03b2…]}`) and this prints Python's
    (`AliasMap(aliases={…})`). Both are debugging spellings and neither is
    parseable.
    """
    try:
        return textcodec.to_text(obj)
    except SchemaError:
        return str(obj)


def render_line(obj: Any) -> str:
    """One render-channel line: the rendering, then a newline."""
    return render(obj) + "\n"


class TextChannel(LineChannel):
    """`#[type] body` lines in, and `text`, `base64` or `render` out."""

    __slots__ = ("_fmt_out",)

    FORMAT: ClassVar[Format] = Format.TEXT

    _ENCODERS: ClassVar[Mapping[Format, Any]] = {
        Format.TEXT: textcodec.encode_line,
        Format.BASE64: lambda obj: textcodec.encode_line(obj, base64_only=True),
        Format.RENDER: render_line,
    }

    def __init__(
        self,
        transport: Transport,
        *,
        fmt_out: str = Format.TEXT,
        registry: Blueprints | None = None,
        max_alloc: int = DEFAULT_MAX_ALLOC,
        allow_unparsed: bool = False,
    ) -> None:
        """`fmt_out` is `text`, `base64` or `render`; the input is always `text`.

        The two directions are independent, matching astral-go's
        `channel.WithFormats`, and only the output has variants: `base64` and
        `render` exist as output alone.
        """
        parsed = parse_format(fmt_out, output=True)
        if parsed not in TEXT_OUTPUT_FORMATS:
            allowed = ", ".join(sorted(f.value for f in TEXT_OUTPUT_FORMATS))
            # A `ParseError` and not a bare `ValueError`: this is the same
            # fault `parse_format` reports for the same input one line above,
            # and a public class refusing a public argument belongs inside the
            # documented `except AstralError`. It is a `ValueError` as well, so
            # nothing that caught one stops working.
            raise ParseError(
                f"TextChannel: {parsed.value} is not one of its output formats "
                f"({allowed})"
            )
        super().__init__(
            transport,
            registry=registry,
            max_alloc=max_alloc,
            allow_unparsed=allow_unparsed,
        )
        self._fmt_out = parsed

    def __repr__(self) -> str:
        return f"TextChannel({self.transport.endpoint!r}, text/{self._fmt_out.value})"

    @property
    def fmt_out(self) -> Format:
        """The output spelling: `text`, `base64` or `render`."""
        return self._fmt_out

    def _decode_line(self, line: str) -> Any:
        return textcodec.decode(line, registry=self._registry)

    def _encode_line(self, obj: Any) -> str:
        return self._ENCODERS[self._fmt_out](obj)
