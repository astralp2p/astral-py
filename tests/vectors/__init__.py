"""Loader and registry for the wire-fidelity vector corpus.

`wire_vectors.json` is pure data and this module keeps it that way: nothing here
encodes, decodes or hashes anything. Every byte in an assertion comes from the
SDK on one side and from the corpus on the other, and the two halves stop being
independent the moment the harness starts computing expected values itself.

## How the harness grows

Each implementation step registers what it can honour and the rest of the corpus
reports as skips, so the suite is green at every step and covers more of the
corpus at each one.

A **codec** turns one astral type's payload into a value and back:

    register_codec("uint8", Codec(decode=..., encode=...))
    register_resolver(fn)      # fn(astral_type) -> Codec | None, for whole families

`decode` receives the payload bytes and must reject trailing bytes; `encode`
returns the payload. The four optional callables -- `to_json`, `from_json`,
`to_text`, `from_text` -- each enable one further aspect for every vector of
that type.

A **provider** answers for a whole framing or derivation, keyed by name:

    set_provider("framing", obj)     # canonical/channel_frame/polymorphic_field
                                     #   (astral_type, payload) -> bytes
    set_provider("object_id", obj)   # preimage(astral_type, payload) -> bytes
                                     # id_of_bytes(preimage) -> "data1..."
    set_provider("line", obj)        # json_line/text_line
                                     #   (astral_type, payload) -> str

A **negative handler** implements one `negative_vectors` entry:

    @register_negative("neg.string8.oversize")
    def _(case: unittest.TestCase, vector: Vector) -> None: ...

One aspect of one vector may be declared unmeasurable, with the reason:

    register_vector_skip("blueprint.struct", "json_emit", "gap.…: …")

Keyed by vector and aspect rather than by astral type, because two vectors of the
same type can differ in whether a gap touches them, and the reason becomes the
skip message so no skip is ever silent.

Which test methods exist is decided by the corpus alone, and every codec,
provider and handler lookup happens inside the test body. Any test module may
therefore register, in any order: discovery imports every module before running
the first test.

## Two places where the corpus overloads a field

Both are properties of the data, not of the SDK, so the harness classifies each
vector rather than guessing per assertion.

- `binary` is a payload everywhere except the `framing.*` vectors, where it is
  the framing artifact itself.
- `json` and `text` are the bare value forms everywhere except the `line.*`
  vectors, `live.json_envelope.*` and `live.dir.alias_map`, where they are whole
  channel lines including the `#[type]` header, the envelope, and any newline.
- `object_id_preimage` / `object_id` describe the vector's own value everywhere
  except the `objectid.*` vectors, where they describe the object the ID *points
  at* -- there, `object_id` equals the vector's own `text`.
"""

from __future__ import annotations

import json
import pathlib
import unittest
from dataclasses import dataclass
from typing import Any, Callable, Final

__all__ = [
    "CORPUS_PATH",
    "FRAMING_KIND",
    "FRAMING_PAYLOAD_SOURCE",
    "Codec",
    "Vector",
    "codec_for",
    "corpus",
    "framing_kind",
    "framing_payload",
    "gaps",
    "negative_handler",
    "negative_vectors",
    "provider",
    "register_codec",
    "register_negative",
    "register_resolver",
    "register_vector_skip",
    "set_provider",
    "vector_by_id",
    "vector_skip",
    "vectors",
]

CORPUS_PATH: Final = pathlib.Path(__file__).with_name("wire_vectors.json")

# `binary` holds a framing artifact rather than a payload.
_FRAMING_IDS: Final = "framing."
# `json` / `text` hold a whole channel line rather than a bare value form.
_LINE_ID_PREFIXES: Final = ("line.", "live.json_envelope.")
_LINE_TEXT_IDS: Final = frozenset({"live.dir.alias_map"})
# `object_id_preimage` / `object_id` describe the object the ID points at.
_DERIVATION_IDS: Final = "objectid."

# A `framing.*` vector records the framing artifact and not the payload inside
# it, so the payload is taken from the vector that does record it. This is a
# cross-reference inside the corpus, not a computed value.
FRAMING_PAYLOAD_SOURCE: Final = {
    "framing.channel.uint32_42": "uint32.42",
    "framing.channel.untyped_blob": "blob.hello",
    "framing.channel.ack": "ack",
    "framing.short.string8_hello": "string8.hello",
    "framing.canonical.uint32_42": "uint32.42",
}

FRAMING_KIND: Final = {
    "framing.channel.": "channel_frame",
    "framing.short.": "polymorphic_field",
    "framing.canonical.": "canonical",
}


@dataclass(frozen=True)
class Vector:
    """One corpus entry, with the corpus's field overloading resolved."""

    raw: dict[str, Any]

    @property
    def id(self) -> str:
        return self.raw["id"]

    @property
    def astral_type(self) -> str:
        return self.raw["astral_type"]

    @property
    def description(self) -> str:
        return self.raw.get("description", "")

    @property
    def source(self) -> str:
        return self.raw.get("source", "")

    @property
    def ref(self) -> str:
        return self.raw.get("ref", "")

    @property
    def notes(self) -> str:
        return self.raw.get("notes", "")

    @property
    def slug(self) -> str:
        return "".join(c if c.isalnum() else "_" for c in self.id)

    # --- classification ---

    @property
    def binary_is_framing(self) -> bool:
        return self.id.startswith(_FRAMING_IDS)

    @property
    def json_is_line(self) -> bool:
        return self.id.startswith(_LINE_ID_PREFIXES)

    @property
    def text_is_line(self) -> bool:
        return self.id.startswith(_LINE_ID_PREFIXES) or self.id in _LINE_TEXT_IDS

    @property
    def object_id_is_derivation(self) -> bool:
        return self.id.startswith(_DERIVATION_IDS)

    # --- fields ---

    def has(self, key: str) -> bool:
        return key in self.raw

    def hex(self, key: str) -> bytes:
        return bytes.fromhex(self.raw[key])

    @property
    def payload(self) -> bytes:
        return self.hex("binary")

    @property
    def json_value(self) -> Any:
        """The `json` field as a JSON *value*.

        Most vectors carry it as JSON text; a few carry it already decoded.
        """
        data = self.raw["json"]
        return json.loads(data) if isinstance(data, str) else data

    @property
    def json_line(self) -> str:
        return self.raw["json"]

    @property
    def text(self) -> str:
        return self.raw["text"]


@dataclass(frozen=True)
class Codec:
    """One astral type's four encodings, as far as they are implemented.

    `decode` must consume its whole input; a payload with bytes left over is a
    frame that did not hold what its type tag claimed.
    """

    decode: Callable[[bytes], Any]
    encode: Callable[[Any], bytes]
    to_json: Callable[[Any], Any] | None = None
    from_json: Callable[[Any], Any] | None = None
    to_text: Callable[[Any], str] | None = None
    from_text: Callable[[str], Any] | None = None


_corpus: dict[str, Any] | None = None
_codecs: dict[str, Codec] = {}
_resolvers: list[Callable[[str], Codec | None]] = []
_providers: dict[str, Any] = {}
_negatives: dict[str, Callable[[unittest.TestCase, Vector], None]] = {}
_skips: dict[tuple[str, str], str] = {}


def corpus() -> dict[str, Any]:
    global _corpus
    if _corpus is None:
        with CORPUS_PATH.open(encoding="utf-8") as fh:
            _corpus = json.load(fh)
    return _corpus


def vectors() -> list[Vector]:
    return [Vector(v) for v in corpus()["vectors"]]


def negative_vectors() -> list[Vector]:
    return [Vector(v) for v in corpus()["negative_vectors"]]


def gaps() -> list[dict[str, Any]]:
    return list(corpus()["gaps"])


def vector_by_id(vector_id: str) -> Vector:
    for raw in corpus()["vectors"]:
        if raw["id"] == vector_id:
            return Vector(raw)
    raise KeyError(f"no vector with id {vector_id!r}")


def framing_kind(vector: Vector) -> str:
    for prefix, name in FRAMING_KIND.items():
        if vector.id.startswith(prefix):
            return name
    raise KeyError(f"{vector.id} is not a framing vector")


def framing_payload(vector: Vector) -> bytes:
    return vector_by_id(FRAMING_PAYLOAD_SOURCE[vector.id]).payload


def register_codec(astral_type: str, codec: Codec) -> None:
    _codecs[astral_type] = codec


def register_resolver(fn: Callable[[str], Codec | None]) -> None:
    _resolvers.append(fn)


def codec_for(astral_type: str) -> Codec | None:
    found = _codecs.get(astral_type)
    if found is not None:
        return found
    for resolve in _resolvers:
        found = resolve(astral_type)
        if found is not None:
            return found
    return None


def set_provider(name: str, obj: Any) -> None:
    _providers[name] = obj


def provider(name: str) -> Any | None:
    return _providers.get(name)


def register_negative(
    vector_id: str,
) -> Callable[
    [Callable[[unittest.TestCase, Vector], None]], Callable[[unittest.TestCase, Vector], None]
]:
    def wrap(
        fn: Callable[[unittest.TestCase, Vector], None],
    ) -> Callable[[unittest.TestCase, Vector], None]:
        _negatives[vector_id] = fn
        return fn

    return wrap


def negative_handler(vector_id: str) -> Callable[[unittest.TestCase, Vector], None] | None:
    return _negatives.get(vector_id)


def register_vector_skip(vector_id: str, aspect: str, reason: str) -> None:
    """Declare one aspect of one vector unmeasurable, naming why.

    The reason must cite a corpus gap or a design divergence: an aspect the
    implementation merely fails is a failure, not a skip.
    """
    _skips[(vector_id, aspect)] = reason


def vector_skip(vector_id: str, aspect: str) -> str | None:
    return _skips.get((vector_id, aspect))
