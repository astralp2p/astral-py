"""The ``objects`` protocol: typed object storage, retrieval and discovery.

Reference: ``protocols/objects/`` (README, ``ops/objects.*.md``, ``types/``),
astral-go ``api/objects/*.go`` + ``api/objects/client/*.go``, and the auth base
(``api/auth/action.go``). This is the largest protocol surface — 25 documented
ops and ~11 records. Ops span five groups:

* **loads / queries** — ``load``, ``read``, ``probe``, ``find``, ``search``,
  ``describe``, ``contains``, ``get_type``, ``spec``, ``blueprints``, ``new``.
* **writes** — ``store``, ``create``, ``push``, ``delete``, ``purge``.
* **repositories** — ``repositories``, ``new_mem``, ``remove_repository``, ``scan``.
* **callbacks** — ``register_searcher`` / ``register_describer`` / ``register_finder``,
  ``register_blueprint``, ``echo``.

Every net-new record here decodes over BOTH framings — binary (``read_from`` /
``write_to``, dispatched from :func:`astral.payload.decode_payload` via the
registry) and JSON (``from_value`` / ``encode_json``) — and, being registered,
can also be SENT (``encode_payload`` / ``to_json_envelope`` dispatch a
:class:`~astral.record.Record`). Field schemas (``FIELDS``) follow the EXACT
astral-go struct order.

Modelling notes / caveats:

* **auth.Action doc-vs-source mismatch (flagged).** The type docs for
  ``mod.objects.create_object_action`` / ``read_object_action`` show the embedded
  ``auth.Action`` as a single ``CallerID`` field. astral-go's actual
  ``api/auth/action.go`` ``Action`` struct is ``Nonce`` (nonce) + ``ActorID``
  (``*astral.Identity``). This module follows the SOURCE (``Nonce`` + ``ActorID``)
  since that is what the binary wire carries; the docs' ``CallerID`` is treated as
  documentation drift. ``astral.Objectify`` flattens the embedded ``Action`` fields
  to the top level over both framings, so the actions are modelled flattened.
  UNCONFIRMED against a live node.
* **RepositoryInfo.Free is uint64 (flagged).** astral-go's ``RepositoryInfo.Free``
  is ``astral.Uint64``; the type doc + ``objects.repositories`` / ``objects.spec``
  examples show a signed ``int64`` (``-1`` sentinel for "not applicable"). This
  module follows the SOURCE (``uint64``). Over binary a ``-1`` sentinel would read
  back as ``0xFFFFFFFFFFFFFFFF``; over JSON the number passes through as-is. Flagged.
* **duration vs Duration.** ``Probe.Time`` is an ``astral.Duration`` (signed int64
  nanoseconds) — modelled with the ``"duration"`` kind. The type/spec docs spell it
  ``duration`` too.
* **TypeSpec / FieldSpec have no astral-go struct.** ``objects.spec`` is documented
  only via its JSON output; there is no Go struct in ``api/objects``. The records
  are reconstructed from the ``objects.type_spec`` type doc and the ``objects.spec``
  op examples: ``TypeSpec`` = ``Name`` (string8) + ``Fields`` (``[]field_spec``);
  each ``FieldSpec`` = ``Name`` (string8) + ``Type`` (string8) + ``Required``
  (bool). ``FieldSpec`` is registered under the INFERRED type ``objects.field_spec``
  (the docs give no wire type name for the element). Binary layout is UNCONFIRMED
  against a live node; the JSON path matches the documented output exactly.

Live-node uncertainties (flagged, none exercised against a running node):

* The ``register_searcher`` / ``register_describer`` / ``register_finder``
  proxied-query handler loop is DEFERRED (see those methods). The keep-alive
  registration (open, read the ack, hold the live :class:`~astral.stream.Stream`)
  is implemented; the loop that serves proxied ``objects.search`` / ``describe`` /
  ``find`` calls back over the same channel is NOT — it needs a serving transport
  and the module's proxy framing, which is unconfirmed. MEDIUM CONFIDENCE.
* The exact ``time`` units for ``Probe.Time`` normalization (nanoseconds assumed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, List, Optional, Tuple, Union

from ..errors import ProtocolError
from ..objectid import ObjectID
from ..objects import AstralObject, blob
from ..record import Record
from ..registry import register
from ..stream import Stream
from . import Protocol

__all__ = [
    "Objects",
    "Probe",
    "RepositoryInfo",
    "Descriptor",
    "SearchResult",
    "TypeSpec",
    "FieldSpec",
    "SearchQuery",
    "QueryTag",
    "CommitMsg",
    "CreateObjectAction",
    "ReadObjectAction",
    "CreateWriter",
]


def _id_str(object_id: Union[str, ObjectID]) -> str:
    return str(object_id)


# ======================================================================
# Records (11) — @register, EXACT astral-go field order
# ======================================================================
@register("mod.objects.probe")
@dataclass(frozen=True)
class Probe(Record):
    """The result of probing an object (``mod.objects.probe``).

    Wire type ``mod.objects.probe`` (astral-go ``api/objects/probe.go``): ``Type``
    (string8 — the astral type name, empty if unstamped), ``Repo`` (string8 — the
    repository it was found in), ``Mime`` (string8 — detected MIME type), ``Time``
    (``astral.Duration`` — signed int64 nanoseconds; modelled as ``"duration"``).
    """

    TYPE = "mod.objects.probe"
    FIELDS = (
        ("type", "Type", "string8"),
        ("repo", "Repo", "string8"),
        ("mime", "Mime", "string8"),
        ("time", "Time", "duration"),
    )

    type: str = ""
    repo: str = ""
    mime: str = ""
    time: int = 0


@register("mod.objects.repository_info")
@dataclass(frozen=True)
class RepositoryInfo(Record):
    """Summary of a registered repository (``mod.objects.repository_info``).

    Wire type ``mod.objects.repository_info`` (astral-go
    ``api/objects/repository_info.go``): ``Name`` (string8), ``Label`` (string8),
    ``Free`` (``astral.Uint64``). NOTE the ``Free`` doc-vs-source split (see the
    module note): the type doc / op examples show a signed ``int64`` with a ``-1``
    sentinel, but the struct is ``Uint64`` — modelled as ``"uint64"`` to match the
    binary wire.
    """

    TYPE = "mod.objects.repository_info"
    FIELDS = (
        ("name", "Name", "string8"),
        ("label", "Label", "string8"),
        ("free", "Free", "uint64"),
    )

    name: str = ""
    label: str = ""
    free: int = 0


@register("mod.objects.describe_result")
@dataclass(frozen=True)
class Descriptor(Record):
    """One descriptor produced by a describer (``mod.objects.describe_result``).

    Wire type ``mod.objects.describe_result`` (astral-go ``api/objects/descriptor.go``):
    ``SourceID`` (``*astral.Identity``), ``ObjectID`` (``*astral.ObjectID``), ``Data``
    (``astral.Object`` — the POLYMORPHIC ``("object",)`` kind: the descriptor payload
    is any registered astral object). Over binary, a mid-struct ``("object",)`` field
    needs its inner type registered to bound the read (see :mod:`astral.record`); over
    JSON it is the ``{"Type", "Object"}`` adapter shape. ``SourceID`` / ``ObjectID`` are
    nullable pointers in Go but the ``"identity"`` / ``"object_id.sha256"`` kinds carry
    their own presence, so they are modelled as plain scalar fields.
    """

    TYPE = "mod.objects.describe_result"
    FIELDS = (
        ("source_id", "SourceID", "identity"),
        ("object_id", "ObjectID", "object_id.sha256"),
        ("data", "Data", ("object",)),
    )

    source_id: str = ""
    object_id: Any = None
    data: Optional[AstralObject] = None


@register("mod.objects.search_result")
@dataclass(frozen=True)
class SearchResult(Record):
    """One deduplicated search hit (``mod.objects.search_result``).

    Wire type ``mod.objects.search_result`` (astral-go ``api/objects/search_result.go``):
    ``SourceID`` (``*astral.Identity``), ``ObjectID`` (``*astral.ObjectID``). Modelled
    with the scalar ``"identity"`` / ``"object_id.sha256"`` kinds (each self-framing).
    """

    TYPE = "mod.objects.search_result"
    FIELDS = (
        ("source_id", "SourceID", "identity"),
        ("object_id", "ObjectID", "object_id.sha256"),
    )

    source_id: str = ""
    object_id: Any = None


@register("objects.field_spec")
@dataclass(frozen=True)
class FieldSpec(Record):
    """One inspectable struct field in an :class:`TypeSpec` (element of ``Fields``).

    Reconstructed from the ``objects.type_spec`` type doc + ``objects.spec`` op
    output (no astral-go struct exists — see the module note): ``Name`` (string8),
    ``Type`` (string8), ``Required`` (bool). Registered under the INFERRED type
    ``objects.field_spec`` (the docs give no wire type name for the element).
    """

    TYPE = "objects.field_spec"
    FIELDS = (
        ("name", "Name", "string8"),
        ("type", "Type", "string8"),
        ("required", "Required", "bool"),
    )

    name: str = ""
    type: str = ""
    required: bool = False


@register("objects.type_spec")
@dataclass(frozen=True)
class TypeSpec(Record):
    """Field-level description of a registered astral struct type (``objects.type_spec``).

    Produced by ``objects.spec`` (astral-go has no struct — see the module note):
    ``Name`` (string8 — the astral type name) and ``Fields`` (``[]field_spec`` — one
    :class:`FieldSpec` per inspectable field), modelled as
    ``("array", ("record", FieldSpec))``.
    """

    TYPE = "objects.type_spec"
    FIELDS = (
        ("name", "Name", "string8"),
        ("fields", "Fields", ("array", ("record", FieldSpec))),
    )

    name: str = ""
    fields: List[FieldSpec] = field(default_factory=list)


@register("objects.query_tag")
@dataclass(frozen=True)
class QueryTag(Record):
    """One tag clause inside a :class:`SearchQuery` (``objects.query_tag``).

    Wire type ``objects.query_tag`` (astral-go ``api/objects/query_tag.go``): ``Name``
    (string8), ``Mod`` (string8 — one of ``""`` require, ``"EXCLUDE"``, ``"OPTIONAL"``,
    ``"OPTIONAL_EXCLUDE"``), ``Value`` (string8). Both name and value are lowercased on
    parse by the node.
    """

    TYPE = "objects.query_tag"
    FIELDS = (
        ("name", "Name", "string8"),
        ("mod", "Mod", "string8"),
        ("value", "Value", "string8"),
    )

    name: str = ""
    mod: str = ""
    value: str = ""


@register("objects.search_query")
@dataclass(frozen=True)
class SearchQuery(Record):
    """A parsed search query (``objects.search_query``).

    Wire type ``objects.search_query`` (astral-go ``api/objects/search_query.go``):
    ``Query`` (string16 — free-text portion) and ``Tags`` (``[]QueryTag`` — parsed tag
    clauses in original order), modelled as ``("array", ("record", QueryTag))``.

    The node's text grammar (``MarshalText`` / ``UnmarshalText``) round-trips a raw
    query string; :meth:`parse` reproduces it so a caller can build the record from a
    ``"mime:text/plain hello"`` string, though ``objects.search`` takes the raw string
    as the ``q`` arg directly.
    """

    TYPE = "objects.search_query"
    FIELDS = (
        ("query", "Query", "string16"),
        ("tags", "Tags", ("array", ("record", QueryTag))),
    )

    query: str = ""
    tags: List[QueryTag] = field(default_factory=list)

    _MODS = {"-": "EXCLUDE", "?": "OPTIONAL", "~": "OPTIONAL_EXCLUDE"}

    @classmethod
    def parse(cls, text: str) -> "SearchQuery":
        """Parse a raw query string into a :class:`SearchQuery`.

        Mirrors astral-go ``SearchQuery.UnmarshalText``: whitespace-split (honouring
        double-quoted spans), bare words accumulate into ``Query`` and ``tag:value``
        tokens become ``Tags``. A leading ``-`` / ``?`` / ``~`` sets the modifier.
        Names and values are lowercased.
        """
        words: List[str] = []
        tags: List[QueryTag] = []
        for token in _tokenize_query(text):
            mod = ""
            if token[:1] in cls._MODS:
                mod = cls._MODS[token[0]]
                token = token[1:]
            name, sep, value = token.partition(":")
            if sep:
                tags.append(
                    QueryTag(name=name.lower(), mod=mod, value=value.lower())
                )
            else:
                words.append(token.lower())
        return cls(query=" ".join(words), tags=tags)


def _tokenize_query(s: str) -> List[str]:
    """Whitespace-split ``s``, respecting double-quoted spans (astral-go ``tokenizeQuery``)."""
    tokens: List[str] = []
    cur: List[str] = []
    in_quote = False
    for ch in s:
        if ch == '"':
            in_quote = not in_quote
        elif ch == " " and not in_quote:
            if cur:
                tokens.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        tokens.append("".join(cur))
    return tokens


@register("mod.objects.commit_msg")
@dataclass(frozen=True)
class CommitMsg(Record):
    """The zero-size sentinel terminating a chunked ``objects.create`` write.

    Wire type ``mod.objects.commit_msg`` (astral-go ``api/objects/commit_msg.go``): an
    EMPTY struct — no ``FIELDS``, no bytes written or read. Receiving it commits the
    open writer and returns the resulting object id.
    """

    TYPE = "mod.objects.commit_msg"
    FIELDS: Tuple = ()


@register("mod.objects.create_object_action")
@dataclass(frozen=True)
class CreateObjectAction(Record):
    """An ``auth.action`` requesting permission to create an object (``mod.objects.create_object_action``).

    Wire type ``mod.objects.create_object_action`` (astral-go
    ``api/objects/create_object_action.go``): embeds ``auth.Action`` and nothing else.
    The embedded ``Action`` (astral-go ``api/auth/action.go``) is ``Nonce`` (nonce) +
    ``ActorID`` (``*astral.Identity``), FLATTENED to the top level by
    ``astral.Objectify``. See the module note on the ``CallerID`` doc-vs-source
    mismatch — the SOURCE fields are used.
    """

    TYPE = "mod.objects.create_object_action"
    FIELDS = (
        ("nonce", "Nonce", "nonce64"),
        ("actor_id", "ActorID", ("ptr", "identity")),
    )

    nonce: str = ""
    actor_id: Optional[str] = None


@register("mod.objects.read_object_action")
@dataclass(frozen=True)
class ReadObjectAction(Record):
    """An ``auth.action`` requesting permission to read an object (``mod.objects.read_object_action``).

    Wire type ``mod.objects.read_object_action`` (astral-go
    ``api/objects/read_object_action.go``): embeds ``auth.Action`` then adds
    ``ObjectID`` (``*astral.ObjectID``). The embedded ``Action`` fields (``Nonce`` +
    ``ActorID``) are FLATTENED to the top level ahead of ``ObjectID`` — see the module
    note on the ``CallerID`` doc-vs-source mismatch.
    """

    TYPE = "mod.objects.read_object_action"
    FIELDS = (
        ("nonce", "Nonce", "nonce64"),
        ("actor_id", "ActorID", ("ptr", "identity")),
        ("object_id", "ObjectID", "object_id.sha256"),
    )

    nonce: str = ""
    actor_id: Optional[str] = None
    object_id: Any = None


# ======================================================================
# The ``objects.create`` writer context helper
# ======================================================================
class CreateWriter:
    """A Writer-style context helper for a live ``objects.create`` channel.

    Mirrors astral-go ``api/objects/client/writer.go``: the channel opens with an
    ``ack`` (already read by :meth:`Objects.create`), stays open for streamed
    ``blob`` chunks, and is closed by :meth:`commit` (sends a
    :class:`CommitMsg`, reads back the ``object_id.sha256``) or :meth:`discard`
    (closes WITHOUT committing, discarding the data).

    Use as a context manager: on a clean exit :meth:`commit` runs automatically
    (unless already committed/discarded); on an exception the writer is discarded.
    Each :meth:`write` sends one untyped ``blob`` chunk (astral-go ``astral.Blob``
    has an empty object type).
    """

    def __init__(self, stream: Stream) -> None:
        self._stream = stream
        self._id: Optional[ObjectID] = None
        self._done = False

    def write(self, data: bytes) -> int:
        """Send one ``blob`` chunk; returns the number of bytes written."""
        if self._done:
            raise ProtocolError("objects.create writer already committed/discarded")
        self._stream.send(blob(bytes(data)))
        return len(data)

    def commit(self) -> ObjectID:
        """Commit the written data: send a :class:`CommitMsg`, read back the id, close."""
        if self._done:
            raise ProtocolError("objects.create writer already committed/discarded")
        self._done = True
        self._stream.send(AstralObject("mod.objects.commit_msg", CommitMsg()))
        value = self._stream.value()
        self._stream.close()
        if value is None:
            raise ProtocolError("objects.create: node did not return an object id")
        self._id = value
        return value

    def discard(self) -> None:
        """Discard the written data (close the channel without committing)."""
        if self._done:
            return
        self._done = True
        self._stream.close()

    def __enter__(self) -> "CreateWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.discard()
        elif not self._done:
            self.commit()


# ======================================================================
# The protocol helper
# ======================================================================
class Objects(Protocol):
    """Typed helpers for the ``objects`` protocol (all 25 documented ops).

    Grounded in ``protocols/objects/ops/`` + ``types/``, astral-go
    ``api/objects/`` + ``api/objects/client/``. Ops group into loads/queries,
    writes, repositories and callbacks (see the module docstring).
    """

    # -- loads / queries ----------------------------------------------------
    def load(
        self,
        object_id: Union[str, ObjectID],
        *,
        repo: Optional[str] = None,
        unparsed: bool = False,
    ) -> Any:
        """Load a stored object and decode it into its typed representation.

        Single-shot when ``object_id`` is given (the streamed-ids form is not
        exposed here). Non-astral payloads come back as raw ``blob`` bytes; a
        registered astral type decodes to a typed :class:`~astral.record.Record`
        over binary. ``unparsed=True`` asks the node to pass raw bytes through
        instead of decoding. Returns the first result's value.
        """
        args: dict = {"id": _id_str(object_id)}
        if repo is not None:
            args["repo"] = repo
        if unparsed:
            args["unparsed"] = True
        return self.client.call_one("objects.load", args)

    def read(
        self,
        object_id: Union[str, ObjectID],
        *,
        offset: int = 0,
        limit: int = 0,
        repo: Optional[str] = None,
    ) -> bytes:
        """Read an object's raw bytes (the response body is unframed).

        Access is gated by ``mod.objects.read_object_action``. ``offset`` / ``limit``
        select a byte range (both default to 0 = from the start, no limit).
        """
        args: dict = {"id": _id_str(object_id)}
        if offset:
            args["offset"] = offset
        if limit:
            args["limit"] = limit
        if repo is not None:
            args["repo"] = repo
        with self.client.query("objects.read", args) as stream:
            return stream.read()

    def probe(
        self, object_id: Union[str, ObjectID], *, repo: Optional[str] = None
    ) -> Probe:
        """Probe an object for its astral type, MIME type, host repo and read latency.

        Returns a single :class:`Probe` (astral-go ``client.Probe``). ``repo`` picks
        the repository to probe in (defaults to the read-default).
        """
        args: dict = {"id": _id_str(object_id)}
        if repo is not None:
            args["repo"] = repo
        return Probe.from_value(self.client.call_one("objects.probe", args))

    def find(self, object_id: Union[str, ObjectID]) -> List[str]:
        """Find identities that can provide the object (astral-go ``client.Find``).

        Streams one ``identity`` per deduplicated provider, then an ``eos``. Returns
        the identities as hex strings.
        """
        return [
            obj.value
            for obj in self.client.call("objects.find", {"id": _id_str(object_id)})
        ]

    def search(
        self, query: Union[str, SearchQuery], *, repo: Optional[str] = None
    ) -> List[SearchResult]:
        """Run a search across registered searchers (astral-go ``client.Search``).

        ``query`` is the raw ``objects.search_query`` grammar string (or a
        :class:`SearchQuery`, sent via its text form). ``repo`` restricts matches to
        objects present in that repository. Streams one
        :class:`SearchResult` per deduplicated hit, then an ``eos``.
        """
        q = _search_query_text(query) if isinstance(query, SearchQuery) else query
        args: dict = {"q": q}
        if repo is not None:
            args["repo"] = repo
        return [
            SearchResult.from_value(obj.value)
            for obj in self.client.call("objects.search", args)
        ]

    def describe(
        self,
        object_id: Union[str, ObjectID],
        *,
        only: Optional[str] = None,
        except_: Optional[str] = None,
    ) -> List[Descriptor]:
        """Collect descriptors for an object from all registered describers.

        Streams one :class:`Descriptor` (``mod.objects.describe_result``) per
        descriptor, then an ``eos``. ``only`` / ``except_`` are comma-separated
        descriptor-type filters. Returns TYPED :class:`Descriptor` records (the
        FIX over the old raw-value ``describe``).
        """
        args: dict = {"id": _id_str(object_id)}
        if only is not None:
            args["only"] = only
        if except_ is not None:
            args["except"] = except_
        return [
            Descriptor.from_value(obj.value)
            for obj in self.client.call("objects.describe", args)
        ]

    def contains(
        self, object_id: Union[str, ObjectID], repo: str
    ) -> bool:
        """Check whether ``repo`` might contain the object (probabilistic).

        ``repo`` is REQUIRED (astral-go / the ``objects.contains`` doc both mark it
        required — the FIX over the old repo-less ``contains``). Returns the single
        ``bool`` result.
        """
        result = self.client.call_one(
            "objects.contains", {"repo": repo, "id": _id_str(object_id)}
        )
        return bool(result)

    def get_type(self, object_id: Union[str, ObjectID]) -> str:
        """Return the object's astral type name as a ``string8`` (deprecated; prefer :meth:`probe`).

        astral-go marks ``GetType`` deprecated in favour of ``Probe``. Returns the
        type-name string; the node errors with ``unknown type`` if the object has no
        astral stamp (surfaced as :class:`~astral.errors.RemoteError`).
        """
        result = self.client.call_one("objects.get_type", {"id": _id_str(object_id)})
        return "" if result is None else str(result)

    def spec(self, type: Optional[str] = None) -> List[TypeSpec]:
        """Describe the fields of registered astral struct types (``objects.spec``).

        Streams one :class:`TypeSpec` per struct type (sorted by name), then an
        ``eos``; when ``type`` is given only that type's spec is returned. Types with
        no inspectable fields are skipped by the node.
        """
        args = {}
        if type is not None:
            args["type"] = type
        return [
            TypeSpec.from_value(obj.value)
            for obj in self.client.call("objects.spec", args)
        ]

    def blueprints(self) -> List[str]:
        """List every registered type name in dependency order (``objects.blueprints``).

        Streams one ``string8`` name per registered type, then an ``eos``.
        """
        return [obj.value for obj in self.client.call("objects.blueprints")]

    def new(self, type: str) -> Any:
        """Construct a zero-valued instance of a registered astral ``type`` (``objects.new``).

        Returns the zero value (a typed :class:`~astral.record.Record` for a
        registered struct over binary, else the scalar/raw value). Returns ``None``
        when ``type`` is not registered — the node replies with a ``nil`` object,
        whose value is ``None``.
        """
        return self.client.call_one("objects.new", {"type": type})

    # -- writes -------------------------------------------------------------
    def store(
        self,
        objects: Iterable[AstralObject],
        *,
        repo: Optional[str] = None,
    ) -> List[ObjectID]:
        """Encode and store typed astral ``objects`` as new repository entries.

        INPUT-BODY op (astral-go ``client.Store`` streams objects, one id back per
        object). Each item is an :class:`~astral.objects.AstralObject` (a typed
        ``(type, value)`` — a registered :class:`~astral.record.Record` value encodes
        over binary, raw bytes pass through). Returns the ``object_id.sha256`` per
        stored object, in order.

        netsim leans on this: send the objects on the body, read one id back per
        object. The node returns an id as each store commits, so this sends all
        inputs, then an ``eos``, then collects the ids.
        """
        items = list(objects)
        args = {}
        if repo is not None:
            args["repo"] = repo
        ids: List[ObjectID] = []
        with self.client.query("objects.store", args) as stream:
            for obj in items:
                stream.send(obj)
            stream.send_eos()
            for result in stream.results():
                ids.append(result.value)
        return ids

    def store_one(
        self, obj: AstralObject, *, repo: Optional[str] = None
    ) -> ObjectID:
        """Store a single object and return its id (convenience over :meth:`store`)."""
        ids = self.store([obj], repo=repo)
        if not ids:
            raise ProtocolError("objects.store: node returned no object id")
        return ids[0]

    def create(
        self, *, repo: Optional[str] = None, alloc: int = 0
    ) -> CreateWriter:
        """Open a chunked write and return a :class:`CreateWriter` (astral-go ``client.Create``).

        Opens the ``objects.create`` channel, reads the ``ack`` acknowledging the open
        writer, and returns a live writer that streams ``blob`` chunks then commits
        with a :class:`CommitMsg` (returning the ``object_id.sha256``) or discards.
        ``repo`` picks the target repository; ``alloc`` is a pre-allocation hint in
        bytes. Use the returned writer as a context manager (auto-commit on clean
        exit, discard on exception)::

            with client.objects.create(repo="local") as w:
                w.write(b"hello")
            oid = w.commit()  # or rely on the context manager's auto-commit
        """
        args = {}
        if alloc > 0:
            args["alloc"] = alloc
        if repo is not None:
            args["repo"] = repo
        stream = self.client.query("objects.create", args)
        # Read the ack acknowledging the open writer before handing the writer back.
        first = stream.recv()
        if first is None:
            stream.close()
            raise ProtocolError("objects.create: channel closed before ack")
        first.raise_for_error()
        if not first.is_ack:
            stream.close()
            raise ProtocolError(
                f"objects.create: expected ack, got {first.type!r}"
            )
        return CreateWriter(stream)

    def push(self, obj: AstralObject) -> bool:
        """Push a single object to the node's receivers (astral-go ``client.Push``).

        Sends the object on the body and returns the acceptance flag: ``True`` if a
        receiver accepted it, ``False`` if it was rejected. Each object is capped at
        32 KiB by the node.
        """
        with self.client.query("objects.push") as stream:
            stream.send(obj)
            return bool(stream.value())

    def delete(
        self, object_id: Union[str, ObjectID], repo: str
    ) -> None:
        """Delete an object from ``repo`` (astral-go ``client.Delete``; acks).

        ``repo`` is REQUIRED (no default repository for delete). The node acks on a
        successful delete; a failure surfaces as :class:`~astral.errors.RemoteError`.
        """
        self.client.call_one(
            "objects.delete", {"repo": repo, "id": _id_str(object_id)}
        )

    def delete_many(
        self, object_ids: Iterable[Union[str, ObjectID]], repo: str
    ) -> int:
        """Delete a STREAM of objects from ``repo`` (the streamed-ids form of ``delete``).

        Streams the ids on the channel body (``id`` omitted from the query args) and
        counts one ``ack`` per successful delete. Returns the ack count.
        """
        ids = [_id_str(i) for i in object_ids]
        acks = 0
        with self.client.query("objects.delete", {"repo": repo}) as stream:
            for i in ids:
                stream.send(AstralObject("object_id.sha256", ObjectID.parse(i)))
            stream.send_eos()
            for obj in stream.results():
                if obj.is_ack:
                    acks += 1
        return acks

    def purge(self, repo: str) -> List[ObjectID]:
        """Purge ``repo`` oldest-read-first, skipping held objects (astral-go ``client.Purge``).

        Streams one ``object_id.sha256`` per purged object, then an ``eos``. Returns
        the purged ids.
        """
        return [
            obj.value for obj in self.client.call("objects.purge", {"repo": repo})
        ]

    # -- repositories -------------------------------------------------------
    def repositories(self) -> List[RepositoryInfo]:
        """List repositories registered with the module (astral-go ``client.Repositories``).

        Streams one :class:`RepositoryInfo` per repository (network zone excluded),
        then an ``eos``.
        """
        return [
            RepositoryInfo.from_value(obj.value)
            for obj in self.client.call("objects.repositories")
        ]

    def new_mem(self, name: str, *, size: Optional[Union[str, int]] = None) -> None:
        """Create a new in-memory repository ``name`` (astral-go ``client.NewMem``; acks).

        ``size`` is the maximum size (e.g. ``"64M"``, ``"1G"``; defaults to the
        module-wide default). The node acks once the repository is created and
        grouped into ``memory``; a name clash or bad size surfaces as
        :class:`~astral.errors.RemoteError`.
        """
        args = {"name": name}
        if size is not None:
            args["size"] = size
        self.client.call_one("objects.new_mem", args)

    def remove_repository(self, name: str) -> None:
        """Remove the repository ``name`` (acks). Built-in repos cannot be removed."""
        self.client.call_one("objects.remove_repository", {"name": name})

    def scan(self, repo: str, *, follow: bool = False) -> Iterator[ObjectID]:
        """Stream the ids of every object in ``repo`` (astral-go ``client.Scan``).

        Yields one :class:`~astral.objectid.ObjectID` per object. When ``follow`` is
        false the stream ends at ``eos``; when true the node keeps the channel open,
        streaming new ids as they are added — a single ``eos`` separates the initial
        snapshot from the live tail, so :meth:`~astral.stream.Stream.follow` is used to
        read across it (the snapshot/live boundary is not surfaced). The follow
        generator runs until the channel closes or the caller breaks out.
        """
        args = {"repo": repo, "follow": follow}
        stream = self.client.query("objects.scan", args)
        if follow:
            def _follow() -> Iterator[ObjectID]:
                try:
                    for obj in stream.follow():
                        yield obj.value
                finally:
                    stream.close()
            return _follow()

        def _snapshot() -> Iterator[ObjectID]:
            try:
                for obj in stream.results():
                    yield obj.value
            finally:
                stream.close()
        return _snapshot()

    # -- callbacks / registrations ------------------------------------------
    def register_searcher(self) -> Stream:
        """Register the caller as an external searcher (KEEP-ALIVE skeleton).

        Opens ``objects.register_searcher``, reads the ``ack`` confirming the
        registration, and returns the LIVE :class:`~astral.stream.Stream` — **keep it
        open**: closing it drops the registration (astral-go ``RegisterSearcher``
        blocks on the ack; the registration lives for the channel's lifetime).

        DEFERRED (MEDIUM CONFIDENCE): the proxied-query handler loop. The node proxies
        ``objects.search`` calls back to the caller's identity over this channel for
        the registration's lifetime; serving those proxied queries (reading a
        ``SearchQuery``, replying with :class:`SearchResult` objects) needs a serving
        transport and the module's proxy framing, which is unconfirmed against a live
        node. This method only holds the registration open. See :meth:`_register`.
        """
        return self._register("objects.register_searcher")

    def register_describer(self) -> Stream:
        """Register the caller as an external describer (KEEP-ALIVE skeleton).

        As :meth:`register_searcher` but for ``objects.describe`` (proxied describe
        calls reply with :class:`Descriptor` objects). The proxied-query handler loop
        is DEFERRED (MEDIUM CONFIDENCE); this holds the registration open.
        """
        return self._register("objects.register_describer")

    def register_finder(self) -> Stream:
        """Register the caller as an external finder (KEEP-ALIVE skeleton).

        As :meth:`register_searcher` but for ``objects.find`` (proxied find calls
        reply with ``identity`` objects). The proxied-query handler loop is DEFERRED
        (MEDIUM CONFIDENCE); this holds the registration open.
        """
        return self._register("objects.register_finder")

    def _register(self, op: str) -> Stream:
        """Open ``op``, read the ack, and return the live Stream holding the registration.

        Shared skeleton for ``register_searcher`` / ``register_describer`` /
        ``register_finder``. The proxied-query serving loop is DEFERRED — see the
        callers. Requires a serving-capable transport to be useful (the caller must
        stay reachable for the proxied callbacks), though the ack read itself works on
        any transport.
        """
        stream = self.client.query(op)
        first = stream.recv()
        if first is None:
            stream.close()
            raise ProtocolError(f"{op}: channel closed before ack")
        first.raise_for_error()
        if not first.is_ack:
            stream.close()
            raise ProtocolError(f"{op}: expected ack, got {first.type!r}")
        return stream

    def register_blueprint(
        self, blueprints: Iterable[AstralObject]
    ) -> List[ObjectID]:
        """Register runtime ``astral.Blueprint`` descriptors (astral-go ``client.Register``).

        INPUT-BODY op: streams the blueprint objects (each an
        :class:`~astral.objects.AstralObject` of type ``astral.Blueprint``), terminated
        by an ``eos``, and reads back one ``object_id.sha256`` per registered
        blueprint (a final ``eos`` closes the stream). Returns the ids.
        """
        items = list(blueprints)
        ids: List[ObjectID] = []
        with self.client.query("objects.register_blueprint") as stream:
            for bp in items:
                stream.send(bp)
            stream.send_eos()
            for result in stream.results():
                ids.append(result.value)
        return ids

    def echo(self, **opts: Any) -> Stream:
        """Open an ``objects.echo`` debug channel and return the LIVE bidirectional Stream.

        The caller drives the sends and receives and must close the returned stream
        (astral-go ``client.Echo``). Options mirror the op: ``only`` / ``except_``
        (comma-separated type filters), ``stop`` (close on this type), ``strict``
        (fail-fast on unregistered blueprints). The node echoes each received object
        back (subject to the filters) until the input closes or a ``stop``-typed
        object arrives.
        """
        args = {}
        for key in ("only", "stop", "strict"):
            if opts.get(key) is not None:
                args[key] = opts[key]
        if opts.get("except_") is not None:
            args["except"] = opts["except_"]
        if not self.client.supports_serving:
            # echo is bidirectional; it degrades on request/response-only transports.
            pass
        return self.client.query("objects.echo", args)


def _search_query_text(q: SearchQuery) -> str:
    """Render a :class:`SearchQuery` back to its raw string form (astral-go ``MarshalText``)."""
    tokens: List[str] = []
    prefixes = {"EXCLUDE": "-", "OPTIONAL": "?", "OPTIONAL_EXCLUDE": "~"}
    for tag in q.tags:
        prefix = prefixes.get(tag.mod, "")
        value = tag.value
        if " " in value:
            value = f'"{value}"'
        tokens.append(f"{prefix}{tag.name}:{value}")
    text = q.query.strip()
    if text:
        if " " in text:
            text = f'"{text}"'
        tokens.append(text)
    return " ".join(tokens)
