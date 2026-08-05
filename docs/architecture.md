# astral-py — architecture of the asyncio SDK

Specification for the from-scratch rewrite of the Python Astral SDK. This document is the
contract implementation agents build from. Every choice here is decided; nothing is left as
an alternative. Where a survey reported a disagreement, §9 records the disagreement, this
document states the resolution, and the resolution is binding.

**Repository:** `/home/intern0/work/astralp2p/astral-py/dev--asyncio-rewrite`
(branch `intern0/dev/asyncio-rewrite`).
**Distribution name:** `astral-ipc`. **Import package:** `astral`. **Console script:**
`astral-query`. All three are unchanged from the legacy `pyproject.toml`.

## 0. Authorities and precedence

| Rank | Authority | Location |
|---|---|---|
| 1 | Live node | `tcp:127.0.0.1:8625`, `unix:~/.apphost.sock`, alias `furry-bolt`, identity `03b2704948bb…ae1` |
| 1 | astral-go | `/home/intern0/work/astralp2p/astral-go/main` @ `5c18d9c` (the commit the node pins) |
| 2 | astrald server | `/home/intern0/work/astralp2p/astrald/master` @ `25f96f17` — authoritative for session semantics the client never exercises |
| 3 | astral-docs | `/home/intern0/work/astralp2p/astral-docs/master` @ `1d6787c` |
| — | Legacy astral-py | `/home/intern0/work/astralp2p/astral-py/master` — **reference only, code discarded** |

When 1 and 3 disagree, 1 wins and the disagreement is filed in §9. When astral-go
contradicts *itself* (there is exactly one such case, §2.9), this document picks the branch
that matches the docs **and** the compile-time path every `api/…` type actually uses, and
makes the decoder tolerant of both.

**Live-node status at time of writing: WEDGED.** `ss -tan` shows 32 `CLOSE-WAIT` sockets on
`127.0.0.1:8625` and a `LISTEN` queue with `Recv-Q 32`; `astrald` (pid 2044259) is alive but
its apphost worker pool is fully consumed and new connections never receive `host_info_msg`.
This is not incidental — it is a **load-bearing architectural constraint** (§3.9) and an
astrald bug report (§9, D-13). Tier-C tests (§7) cannot run until the node is restarted.

## 0.1 Scope

- **Tier 1 modules:** `apphost`, `dir`, `tree`, `crypto`, `auth`, `objects`, `services`.
- **Tier 2:** `user`, `bip137sig`, `ip`, `exonet`.
- **Tier 3, gated experimental:** `nodes`, `nat`.
- **Plus:** the `astral-query` CLI and a `shell.spec` introspection helper.
- **Excluded as modules:** `gateway`, `indexing`, `kcp`, `tcp`, `tor`, and `secp256k1` (its
  one op and four pure helpers fold into `crypto`). Their **wire types** are not excluded:
  `mod.tcp.endpoint`, `mod.tor.endpoint`, `mod.gateway.endpoint` and `mod.kcp.endpoint` are
  required to decode `mod.nodes.node_info` (numeric tags 0/1/2, an unknown tag is a hard
  decode error) and `mod.nodes.link_info`, so codec-only implementations ship in
  `astral/api/endpoints.py`. Excluding a module means excluding its ops, not its types.

Op inventory is **not** restated here. The authoritative inventory is
`survey-go-api.md` §2–§9 (93 in-scope ops + `secp256k1.new` + `shell.spec`), which is itself
derived from the live `shell.spec` registry of 118 ops. Module client code cites that
document by op name; this document specifies only the *pattern* each op-mode follows (§5).

---

# 1. Package layout

Three layers, mirroring astral-go: **wire core** (I/O-free, synchronous), **transport and
session** (async), **module clients** (async). The dependency arrow points one way only:
module clients → session → channel → transport, and every one of them → wire core. The wire
core imports nothing from the other two.

```
src/astral/
  __init__.py            Public façade. Re-exports connect, Client, Identity, ObjectID,
                         Zone, the exception hierarchy, and nothing else.
  py.typed               PEP 561 marker.
  errors.py              The whole exception hierarchy. Imports nothing from astral.

  --- LAYER 1: WIRE CORE (I/O-free, synchronous, no asyncio import anywhere) ---
  wire.py                Reader/Writer over a bytes buffer + offset. Big-endian scalar
                         primitives, length-prefixed strings/bytes, allocation caps, strict
                         short-read errors. The only module that touches struct.pack.
  types.py               Value types: Identity, Nonce, ObjectID, Time, Duration, Zone, Size.
                         Frozen, hashable, with parse()/__str__/JSON forms.
  spec.py                The seven Spec carriers (Primitive/Ref/Slice/Array/Map/Ptr/Any),
                         the primitive + map-key allowlists, and spec validation.
  record.py              @record / @alias / wire() declaration syntax; the FIELDS walker
                         that drives binary, JSON and text from one schema; the Custom
                         escape hatch.
  registry.py            Blueprints: name -> record class | Blueprint. Parent chain,
                         new(name), add(), register_blueprint(), ordering for sync.
  object.py              The Object protocol; Blob (untyped), UnparsedObject, EmptyObject,
                         Ack, EOS, Nil, ErrorMessage, ErrUnexpectedObject, Bundle, Query.
  primitives.py          The registered scalar object types (uint8..uint64, int8..int64,
                         float32/64, bool, string8..64, bytes8..64, time, duration, identity,
                         nonce64, object_id.sha256, zone, size, object_type, stamp).
  blueprint.py           Blueprint/Field and the seven *_spec types as ordinary records
                         (self-hosting), plus RuntimeRecord: a record whose FIELDS came off
                         the wire. Depth guard, cycle detection.
  objectid.py            Canonical form, the typed and untyped ID paths, zBase32, data1.
  codec/
    __init__.py          encode()/decode(); Short, Canonical and Indexed type encoders.
    binary.py            Spec-driven payload codec. The single source of the presence-byte,
                         map-sort and container rules.
    jsoncodec.py         JSON marshal/unmarshal for every spec kind + the {Type,Object}
                         envelope. Named jsoncodec to avoid shadowing stdlib json.
    text.py              Text encode/parse (#[type] sep body) and the bare payload-only
                         form used by query-string parameters.
  querystring.py         Query-string build/parse: op name, url-encoding, sorted keys, the
                         'arg' positional key, per-type parameter text forms.

  --- LAYER 2: TRANSPORT AND SESSION (async) ---
  transport/
    __init__.py          dial(), listen(), listen_any(); endpoint string parsing.
    base.py              Transport ABC (byte stream) and Server ABC. No framing knowledge.
    socket.py            StreamTransport over asyncio TCP and unix sockets.
    mem.py               MemTransport: an in-process duplex pair, for tests and for
                         exercising the session state machine with no kernel involved.
    websocket.py         Minimal RFC 6455 client (no extensions) + WebSocketByteTransport
                         for the astral.binary.v1 subprotocol.
    http.py              One-shot HTTP/1.1 request transport. Query only, never serving.
  channel/
    __init__.py          Channel ABC + open_channel(transport, fmt_in, fmt_out).
    binary.py            BinaryChannel: string8(type) ++ bytes32(payload). allow_unparsed.
                         The only channel that supports detach().
    jsonl.py             JSONLinesChannel + WebSocketJSONChannel (astral.json.v1).
    textchan.py          TextChannel (in and out), base64 and render output variants.
    canonical.py         CanonicalChannel: Stamp ++ string8(type) ++ payload, error-latching.
  session.py             THE apphost session state machine, written once: handshake, auth,
                         route_query, register_service, attach_query, reject_incoming, bind,
                         and the channel -> raw-stream handover.
  conn.py                QueryStream: the accepted query's bidirectional stream, with a raw
                         byte view and a framed object view over the same transport.
  context.py             Frozen Context{identity, zone, filters} with with_* copies. Carries
                         no cancellation — asyncio owns that.

  --- LAYER 3: CLIENT, SERVING, MODULE CLIENTS ---
  client.py              Client façade: query/call/call_one/call_raw/stream/serve, the
                         connection semaphore, the endpoint+token resolution rules, connect().
  stream.py              Stream: async iteration, follow(), snapshot()/live(), send/send_eos,
                         raw byte IO, deterministic aclose().
  serve.py               Inbound serving: Service, PendingQuery, the op dispatch table, the
                         register-handler listener, and the gated register-service path.
  registrar.py           apphost.bind + apphost.register_handler lifecycle, post-connect
                         hooks, reconnect with exponential backoff, the replaced-Event gate.
  api/
    __init__.py          Eager import of every module below. Importing astral.api guarantees
                         every wire type is registered. Never rely on lazy attribute access.
    apphost.py           Tier 1. apphost.* ops + all mod.apphost.* message types.
    dir.py               Tier 1. dir.* ops, mod.dir.alias_map (the map-kind proof).
    tree.py              Tier 1. tree.* ops, mod.tree.err_no_value.
    crypto.py            Tier 1. crypto.* ops + secp256k1.new + the four pure helpers.
    auth.py              Tier 1. auth.* ops, contract/permit/action types.
    objects.py           Tier 1, largest. 25 ops, the Writer protocol, the search grammar.
    services.py          Tier 1. services.discover/sync, services.update.
    user.py              Tier 2. 15 ops incl. the non-EOS sync_assets stream.
    bip137sig.py         Tier 2. Four ops; local mnemonic/seed via bip39.py.
    ip.py                Tier 2. Three ops, mod.ip.ip_address.
    exonet.py            Tier 2. Endpoint ABC + endpoint type registry.
    endpoints.py         Codec-only tcp/tor/gateway/kcp endpoint types (no dialing).
    nodes.py             Tier 3, gated. Seven ops, link/session info, node_info base62.
    nat.py               Tier 3, gated. Three of five ops (see §4.7).
    shell.py             shell.spec -> routing.op_spec. Introspection helper.
  bip39.py               BIP-39 wordlist + entropy/mnemonic/seed. Pure stdlib.
  cli.py                 astral-query.
```

`pyproject.toml` changes: `requires-python = ">=3.11"`, classifiers updated to 3.11–3.14,
`dependencies = []` retained, one optional extra `[project.optional-dependencies] secp256k1 =
["coincurve>=19"]`. Everything else unchanged.

---

# 2. The wire core

The wire core is **synchronous and I/O-free**. This is not an oversight in an asyncio
rewrite; it is forced by the wire format. Every framing the SDK speaks is length-delimited
or line-delimited, so the complete payload is always in memory before decoding starts. An
`await` inside a scalar decoder would buy nothing and cost a coroutine per field. Decoders
take a `Reader` over `bytes`; encoders write into a `Writer` over a `bytearray`. Only
`channel/` and `transport/` are async.

Corollary, and it is a hard rule: types that read to EOF (`Blob`, `UnparsedObject`) must
receive a reader bounded to exactly one frame's payload. They must never see the socket.

## 2.1 Global rules

| Rule | Value |
|---|---|
| Byte order | Big-endian, everywhere, no exceptions |
| Signed integers | Two's complement |
| Floats | IEEE 754, `struct.pack(">f")` / `(">d")` |
| Varints | None exist |
| Alignment / padding | None |
| Field names on the binary wire | Never. Order is the schema. |
| Byte counts returned by codecs | Not returned. Derive from `Reader.pos`. astral-go's `n` values are wrong for eight types (`survey-go-core.md` §11); reproducing them would be reproducing a bug. |

`wire.Reader` raises `ShortRead` (a subclass of `WireError`) on any read past the end and
**assigns nothing** — astral-go's `String16.ReadFrom` returns partial data alongside the
error; we do not. Every length-prefixed reader checks the declared length against a
configurable `max_alloc` (default 64 MiB) **before** allocating, because a `string64` /
`bytes64` length prefix and a `uint32` container count are attacker-controlled.

`wire.Writer` for length-prefixed types **buffers the payload, checks the cap, then writes**.
Oversize input raises `ValueError("string8: data too large")` and leaves the buffer
untouched. Never write a truncated length.

## 2.2 Primitive types

Complete table. "Wire" is the payload only, with no type tag and no length framing.

| Object type | Wire | Python | JSON | Text |
|---|---|---|---|---|
| `uint8/16/32/64` | 1/2/4/8 B BE | `int`, range-checked | number | decimal |
| `int8/16/32/64` | 1/2/4/8 B BE two's complement | `int`, range-checked | number | decimal, parsed **at the correct width** (astral-go parses all widths as int8; that is a bug, §9 G-4) |
| `float32/64` | 4/8 B IEEE 754 BE | `float` | number; **raise on NaN/Inf** rather than emitting Python's non-standard `NaN`/`Infinity` | shortest repr, `'f'` style, never exponent |
| `bool` | 1 B | `bool` | `true`/`false` | `true`/`false`; parse accepts `true/yes/t/y/1` and `false/no/f/n/0`, case-insensitive |
| `string8/16/32/64` | `uintN` len ++ UTF-8 | `str` | string | raw string |
| `bytes8/16/32/64` | `uintN` len ++ raw | `bytes` | base64, **std alphabet with `=` padding** | same base64 |
| `identity` | **33 raw bytes, no flag** | `Identity` | 66-hex, or `"anyone"` when zero | 66-hex (**never** `"anyone"` on emit); parse accepts `anyone`, 66 zeros, or 66 hex |
| `nonce64` | 8 B BE | `Nonce(int)` | hex, **unpadded** (bug-compatible with Go) | `%016x` |
| `object_id.sha256` | `uint64 Size` ++ 32 B hash = 40 B | `ObjectID` | `data1…`; `""` when zero | `data1…` (zero renders `data1`) |
| `time` | `uint64` of UnixNano | `Time` (int nanos) | RFC 3339 with nanos, UTC `Z` | same |
| `duration` | **signed** `int64` nanos | `Duration` (int nanos) | integer nanoseconds | Go duration string (`1m30s`) |
| `zone` | 1 B bitmask d=1 v=2 n=4 | `Zone(IntFlag)` | **string** `"dvn"`, not a number | `"dvn"` |
| `size` | `uint64` | `Size(int)` | number | **decimal** — note `str(Size)` is the human form `1.5KiB`, which is *not* the text encoding |
| `object_type` | `string8` | `str` | string | string |
| `stamp` | 4 B `41 44 43 30` | `Stamp` singleton | — | — |
| `ack`, `eos`, `nil` | zero bytes | singletons | `null` | `""` (Go emits `#[ack] ` with a trailing space; accept both) |
| `error_message` | `string16` | `ErrorMessage(str)` | string | the message |
| `blob` (untyped) | raw bytes to EOF | `Blob(bytes)` | base64 | base64 |
| `err_unexpected_object` | `string8(innerType) ++ innerPayload` | record with one `Any()` field | envelope | — |
| `query` | `nonce64 ++ Ptr(identity) ++ Ptr(identity) ++ string32` | record | envelope | — |
| `bundle` | `uint32 count ++ bytes32(string8(type) ++ payload) × count` | `Bundle` | array of envelopes | — |

Decisions embedded above that must not be re-litigated:

1. **`identity` is 33 flat bytes.** The legacy SDK modelled it as a presence byte plus 33
   bytes and claimed live verification; that was a misattribution — the presence byte belongs
   to the enclosing `*astral.Identity` **pointer field**. Live `apphost.whoami` returns a
   33-byte `identity` payload with no flag. `Ptr("identity")` is the optional wrapper and it
   is what every `api/…` struct field uses. This one error broke `dir.resolve`,
   `apphost.whoami`, `objects.find` and `user.list_siblings` over binary in the legacy SDK.
2. **`bool` decoding is lenient, presence flags are strict.** Two different readers. Any
   non-zero byte decodes as `True` for a `bool` payload; only `0x00`/`0x01` are accepted for
   a pointer nil-flag, and only `0x01` for a synthesized container presence byte.
3. **Strings are `str`, encoded UTF-8 with `errors="surrogateescape"`** on both directions.
   Go strings are byte containers; surrogateescape is the only encoding that round-trips
   arbitrary bytes through `str` byte-exactly, which ObjectID stability requires. Never use
   `errors="replace"` — it silently corrupts content hashes.
4. **`Time` and `Duration` keep integer nanoseconds as the canonical field.** `datetime` has
   microsecond resolution; storing one loses the low three digits and every ObjectID over a
   time-bearing object then mismatches. `.datetime` / `.timedelta` are lossy conveniences.
5. **`Nonce` is an `int` subclass** whose `__str__` is `%016x`, so CLI and log output are
   right by construction while arithmetic and dict keys still work.
6. **`Zone` is an `enum.IntFlag`.** `Zone.parse(s)` ORs recognised letters and **silently
   ignores unknown characters** (matching `astral.Zones`); the empty string yields `Zone(0)`,
   not the default. The legacy raised on unknown letters; that was stricter than the protocol.

## 2.3 Composite kinds

Seven, mirroring astral-go's `Spec` carriers exactly. The map kind, absent from the legacy
SDK, is the reason `dir.alias_map` was undecodable.

```
Primitive(name)              the named primitive's payload. name must be on the allowlist.
Ref(type)                    the referenced type's payload, INLINED BARE: no tag, no length,
                             no presence byte. This is also how an embedded value struct
                             encodes.
Slice(type="")               uint32 count ++ element × count. type="" => heterogeneous.
Array(type, length)          element × length. NO count on the wire; length is in the schema.
Map(key, value="")           uint32 count ++ (key ++ value) × count, SORTED BY ENCODED KEY
                             BYTES. key in {string16, uint8, uint16, uint32, uint64}.
Ptr(type)                    0x00 absent / 0x01 ++ payload. Anything else is corrupt.
Any()                        string8(type) ++ payload; a zero-length tag means nil.
```

**The presence byte is one rule with three faces. Encode it from the spec, never from the
value.**

```python
def needs_presence(spec) -> bool:
    return not isinstance(spec, (Ptr, Any))
```

- `Ptr` emits its own nil flag (`0x00` or `0x01`).
- `Any` emits its own type tag; a zero-length tag is the nil signal.
- Everything else, when it sits inside a slice element, an array element, or a **map value**
  slot, is preceded by a synthesized `0x01`. **Map keys never carry one.**
- On **write** emit `0x01`. On **read** accept `0x01`, and additionally accept `0x00` as
  "absent → `None`". astral-go's reflection codec rejects `0x00` in a value slot, but its
  blueprint-built containers use `*T` elements and legally emit `0x00`; a decoder that
  assumes `0x01` desynchronises on a blueprint peer. Being permissive on read and strict on
  write is byte-compatible with both and cannot corrupt anything.

**Map sort order is part of the wire format, not a nicety.** Encode each key and each value
into separate buffers, sort the pairs by `bytes` comparison of the **encoded key**, then
emit. `string16` keys therefore sort by length prefix first, then bytes. Python dict
insertion order must never reach the wire; content hashes depend on this.

`count == 0` decodes to an **empty container** (`[]` / `{}`), not `None`. astral-go leaves
a zero-count map nil and a zero-count slice empty — an internal asymmetry with no wire
consequence, since both encode as `00 00 00 00`. We normalise to empty and special-case the
JSON emission of an explicitly-absent map.

Allocation guard: after reading a `uint32` count, refuse to pre-allocate. Append as elements
decode, and abort on `ShortRead`. A hostile four-billion count must cost bytes, not gigabytes.

Depth guard: `MAX_DEPTH = 64` on nested record frames, enforced on encode, on decode, **and
at runtime-record construction** (a `Ref` cycle recurses through spec-zero construction).
Unlike astral-go, we additionally detect **two-step** `Ref`/`Ptr` cycles at registration
time; astral-go only catches one-step self-reference and stack-overflows on a mutual pair.
`Array.length` is capped at 65 536 and rejected at registration.

## 2.4 The Object model

```python
class Object(Protocol):
    ASTRAL_TYPE: ClassVar[str]           # "" for an untyped object
    def write_payload(self, w: Writer) -> None: ...
    @classmethod
    def read_payload(cls, r: Reader) -> Self: ...
```

Three invariants, inherited from astral-go and non-negotiable:

1. `write_payload` / `read_payload` handle the **payload only**. They never write or read a
   type tag and never write a length prefix. Framing belongs to whoever owns the stream.
2. `read_payload` may read greedily to the end of its reader. Framed receivers therefore must
   hand it a `Reader` over exactly one frame's payload.
3. The type string lives on the class, never in the payload.

`Blob` is the untyped object: `ASTRAL_TYPE == ""`, payload is raw bytes, `read_payload` reads
to the end. It is **not** in the registry (astral-go's `Add` rejects an empty type and
swallows the error); the binary channel maps a zero-length type tag to `Blob` by an explicit
special case, exactly as `BinaryReceiver` does.

`UnparsedObject(type, payload)` carries a type name the registry does not know, with its raw
payload preserved. Produced only when a channel opts in via `allow_unparsed=True`. It has no
JSON and no text form; marshalling it raises.

## 2.5 The schema mechanism — what replaces Go reflection

Go uses reflection for exactly two jobs: deriving a schema from a compiled struct type, and
walking a value generically. Python needs a different answer for each.

**Schema derivation is deleted.** Python type hints are width-free: `str` cannot distinguish
`string8` from `string32`, `int` cannot distinguish `uint8` from `int64`, `bytes` cannot
distinguish `bytes8` from `identity`. Any introspection scheme degenerates into
`Annotated[str, String16]`, which *is* an explicit schema with worse ergonomics, worse error
messages, a hard dependency on `typing.get_type_hints` resolution order, and no way to
express a heterogeneous container or a fixed-length array at all. **The Spec tree is
declared directly and is the single source of truth.**

**Value walking becomes a table-driven walker over the Spec tree**, reading and writing
attributes by name. No `inspect`, no `__annotations__` parsing, no struct tags.

### The declaration syntax

A record is a `dataclass` whose fields carry their wire spec in `field(metadata=...)`. One
declaration site, no duplication, order guaranteed by `dataclasses.fields()`.

```python
# astral/record.py
def wire(name: str, spec: Spec, *, default: Any = _UNSET) -> Any:
    """Declare a wire field. `name` is the PascalCase JSON/text name; `spec` is the wire
    shape. When `default` is omitted the spec-zero is used, so field order is never
    constrained by dataclass default rules."""

def record(type_name: str, *, registry: Blueprints | None = None): ...
def alias(type_name: str, underlying: str): ...
```

`@record(t)` applies `@dataclass(slots=True, kw_only=True, eq=True, repr=True)`, reads
`dataclasses.fields(cls)` in declaration order into `cls.FIELDS: tuple[F, ...]` where
`F = (attr, wire_name, spec)`, sets `cls.ASTRAL_TYPE = t`, validates the whole thing, and
registers the class. `kw_only=True` removes the "defaults must come last" constraint
entirely and makes six-field protocol messages readable at the call site; positional
construction of wire messages is a bug farm and is not offered.

Worked example — `mod.apphost.route_query_msg`, the message that carries every outbound
query:

```python
from astral.record import record, wire
from astral.spec import Primitive, Ptr, Slice
from astral.types import Identity, Nonce, Zone

@record("mod.apphost.route_query_msg")
class RouteQueryMsg:
    nonce:   Nonce           = wire("Nonce",   Primitive("nonce64"))
    caller:  Identity | None = wire("Caller",  Ptr("identity"))
    target:  Identity | None = wire("Target",  Ptr("identity"))
    query:   str             = wire("Query",   Primitive("string16"))
    zone:    Zone            = wire("Zone",    Primitive("zone"), default=Zone.ALL)
    filters: list[str]       = wire("Filters", Slice("string8"))
```

Encoding `RouteQueryMsg(nonce=Nonce(0x1122334455667788), caller=None,
target=Identity.parse("03b27049…ae1"), query="apphost.whoami", zone=Zone.ALL, filters=[])`
produces, byte for byte:

```
1122334455667788                       Nonce            nonce64, 8 B BE
00                                     Caller           Ptr nil flag, absent
01 03b27049…ae1                        Target           Ptr present + 33 raw identity bytes
000e 617070686f73742e77686f616d69      Query            string16 len 14 + "apphost.whoami"
07                                     Zone             uint8 bitmask dvn
00000000                               Filters          uint32 count = 0
```

and with `filters=["abc"]` the tail becomes `00000001 01 03 616263` — count, the synthesized
presence byte (because `string8` is neither `Ptr` nor `Any`), then the `string8`. The legacy
SDK's `messages.py` omitted that presence byte while its `record.py` emitted it; nobody
noticed because it never sent filters. One codec, one rule, no second implementation.

The same `FIELDS` tuple drives all four façades: `codec.binary` walks it for binary,
`codec.jsoncodec` walks it keyed by `wire_name`, `codec.text` walks it for the text form, and
`blueprint.of(cls)` converts it into an `astral.blueprint` object for
`objects.register_blueprint`. Writing a fifth façade later costs one function, not N types.

### Embedded structs

astral-go embeds structs by value (`Action` inside `CreateObjectAction`) and by pointer
(`*Contract` inside `SignedContract`). On the binary wire a value embed is **flattened** and
a pointer embed is a nil-flag plus the inlined payload. In JSON, `structValue.MarshalJSON`
uses the Go field name, which for an embedded field is its **type name**, so JSON is
**nested** under `"Action"` / `"Contract"`. The legacy SDK asserted JSON was flattened; it is
not.

No new spec kind is needed. A value embed is `Ref(type)` with `wire_name` set to the Go type
name; a pointer embed is `Ptr(type)` with the same. An `embed(name, type, *, optional=False)`
helper emits the right one and additionally installs forwarding properties so
`signed_contract.issuer` works without reaching through `.contract`. Binary flattening and
JSON nesting fall out of the existing rules.

```python
@record("mod.auth.signed_contract")
class SignedContract:
    contract:   Contract | None  = embed("Contract", "mod.auth.contract", optional=True)
    issuer_sig: Signature | None = wire("IssuerSig",  Ptr("mod.crypto.signature"))
    subject_sig: Signature | None = wire("SubjectSig", Ptr("mod.crypto.signature"))
```

### The escape hatch

Four wire types cannot be expressed declaratively. A record class may define
`write_payload` / `read_payload` directly, in which case `FIELDS` is used only for JSON and
the blueprint is marked non-derivable. The complete list — no others are permitted without
amending this document:

| Type | Why |
|---|---|
| `mod.tor.endpoint` | `Digest` is 35 raw bytes with no length prefix |
| `mod.nodes.node_info` | Hand-rolled numeric endpoint tags (0=tcp, 1=tor, 2=gateway), base62 text form |
| `bip137sig.entropy` | `bytes8` plus a validator: length ∈ [16,32] step 4, enforced on encode *and* decode |
| `mod.ip.ip_address` | `bytes8` whose length (4 or 16) selects the IPv4/IPv6 text form |

## 2.6 The registry

```python
class Blueprints:
    parent: "Blueprints | None"
    def add(self, *classes) -> None                  # compile-time record classes
    def register_blueprint(self, bp: Blueprint) -> ObjectID
    def new(self, type_name: str) -> Object | None   # zero value; None if unknown
    def has(self, type_name: str) -> bool            # walks the parent chain
    def ordered(self) -> list[str]                   # for blueprint sync
```

Rules ported verbatim: names are unique across the whole parent chain (a child cannot shadow
a parent); an empty type name is rejected; `new("")` returns `None`; registering a blueprint
validates it, checks closure (every `ReferencedType()` already registered), deep-clones it,
and returns the ObjectID of its canonical form.

**The registry travels with the decode call, not as a module global.** `decode(reader,
registry=…)` threads the registry into every nested frame, so a per-call registry scopes an
entire object graph. astral-go does this for binary and admits it does *not* for JSON; we do
it for all four codecs.

Two allowlists, ported exactly:

```
primitive:  string8/16/32/64  uint8/16/32/64  bytes8/16/32/64
            bool time identity object_id.sha256 nonce64 duration zone        (19 names)
map key:    string16 uint8 uint16 uint32 uint64
```

`int8..int64`, `float32/64`, `size`, `error_message`, `object_type` are registered and fully
encodable, but are **not** on the primitive allowlist, so a runtime blueprint may only reach
them via `Ref(name)`. The **scalar codec table must therefore be wider than the allowlist**:
`Ref("int64")` must resolve, while `Primitive("int64")` must be rejected at declaration.

Name discipline: printable ASCII `0x20..0x7E`, non-empty, ≤255 bytes for both a type name
and a field name; field names unique **case-insensitively** within a record (so the
binary-validated schema matches the case-insensitive JSON decoder).

## 2.7 ObjectID

Two explicit code paths, chosen by typed-ness. Do not port astral-go's `ResolveObjectID`
verbatim — it always writes the stamp and the type header, so calling it on an untyped
`Blob(b"hello")` yields size 10 instead of 5 and an ID that nothing else in the system agrees
with.

```python
def object_id(obj: Object) -> ObjectID:
    """Typed objects only. Raises on an empty ASTRAL_TYPE."""
    canonical = STAMP + string8(obj.ASTRAL_TYPE) + payload_bytes(obj)
    return ObjectID(size=len(canonical), hash=sha256(canonical).digest())

def object_id_of_bytes(data: bytes) -> ObjectID:
    return ObjectID(size=len(data), hash=sha256(data).digest())

def object_id_of_stream(reader) -> ObjectID    # streaming, for objects.create/read
```

`STAMP = b"\x41\x44\x43\x30"` — the big-endian `uint32` `0x41444330`, ASCII `ADC0`.

Text form: zBase32 of the 40 bytes with alphabet `ybndrfg8ejkmcpqxot1uwisza345h769` (40 bytes
= 320 bits = exactly 64 symbols, never any padding), **leading `y` characters stripped**,
prefixed `data1`. Parsing reverses: strip `data1`, left-pad with `y` to 64 chars, decode,
split 8/32. The primitive-type doc omits the `y`-stripping; omitting it produces a 69-char ID
and every comparison fails.

`is_zero` inspects **the hash only**, matching astral-go; a zero ID serialises as 40 zero
bytes with `Size` dropped. JSON emits `""` for a zero ID, and — unlike astral-go — **we
accept `""` on parse** as the zero ID. Go's asymmetry there is a bug we decline to inherit.

Reference vectors, verified this session against astral-go and an independent Python
reimplementation. These are test fixtures, not examples:

| Object | Preimage (hex) | ObjectID |
|---|---|---|
| `uint32(42)` | `414443300675696e7433320000002a` | `data19kygic9q9ibq4ibaikrw9ci76kj6fs1jitxk6wjbwnkrezt8q5jk` |
| `string8("hello")` | `4144433007737472696e67380568656c6c6f` | `data1brwgb65sy54z9imojxaaof9btx3nujt1rxqyozt9ahxm189hi36e1` |
| `ack` | `414443300361636b` | `data1o3dutabz1sm1zyyueipc3q18dam6aszrte4hqtmfspxtkje17npe` |
| `eos` | `4144433003656f73` | `data1t45yb4f1o4atw33k85dbo78uudnw4eoju7z7jo5ba5p53rqyz5ft` |
| raw `hello` (untyped) | `68656c6c6f` | `data1km81js7f9cfdbauqoq3kash6f8o5naxfa878ejx8gbbuckjazgbr` |
| empty object | *(empty)* | `data1ba7oatbjt9yhn1pxz7geufz51jb8i3y6e3r51pgkjfc3dphffqni` |

## 2.8 Framings

Payload encoding never contains the type. Four framings exist and the **type tag sits in a
different place in each** — this is the single most common reimplementation error:

| Container | Layout |
|---|---|
| Binary channel frame | `string8(type)` ++ `bytes32(payload)` — type **outside** the length |
| Bundle element | `bytes32( string8(type) ++ payload )` — type **inside** the length |
| Canonical | `Stamp` ++ `string8(type)` ++ `payload` — **no length at all** |
| Polymorphic (`Any`) field | `string8(type)` ++ `payload` — no length |

Three type encoders, in `codec/__init__.py`: `Short` (`string8(type)`, the default), `Canonical`
(`Stamp ++ string8(type)`, used for ObjectID preimages and the `canonical` channel), `Indexed`
(`uint8` into a closed table). **All three reject an empty type.** The untyped-blob path on a
binary channel bypasses the encoder and writes `string8("")` directly; the docs imply `Short`
can encode an untyped object and it cannot.

An unknown type name mid-payload is **fatal for that stream** — nothing at field granularity
carries a length, so there is no way to resume. Raise `StreamCorrupted` wrapping
`BlueprintNotFound`. Only the binary **channel** layer can recover, via `allow_unparsed`,
because its `bytes32` frame length lets it skip.

## 2.9 The one astral-go self-contradiction: `Any` nil

The reflection codec writes a nil polymorphic field as `0x00` (a zero-length type tag), which
is what `binary-encoding.md` mandates and what every compile-time `api/…` type produces. The
runtime-blueprint codec writes `03 6e 69 6c` (`string8("nil")`) and then **fails to read its
own output**, because `New("")` returns nil. astral-go contradicts itself, so "live node
wins" does not resolve it.

**Decision: write `0x00`. On read, accept both `0x00` and `string8("nil")` as absent.**
Rationale: `0x00` is the documented form and the form produced by every type the SDK will
actually exchange; accepting both costs one branch and makes us interoperable with a peer
using the runtime path. This is an astral-go bug report, not a docs bug report.

## 2.10 Blueprints as self-hosted records

`Blueprint`, `Field` and the seven `*_spec` carriers are declared as ordinary records in
`astral/blueprint.py`. That buys `objects.register_blueprint` for free, lets the SDK decode
an `astral.blueprint` handed to it by a peer, and makes every validation rule testable in
isolation. Verified wire layout, to be pinned as golden vectors:

```
astral.blueprint                = string16 Type ++ uint32 count ++ (0x01 ++ Field)×count
                                  ++ string16 Underlying
astral.blueprint.field          = string16 Name ++ string8 SpecType ++ SpecPayload
astral.blueprint.primitive_spec = string16 PrimitiveType
astral.blueprint.ref_spec       = string16 Type
astral.blueprint.slice_spec     = string16 Type
astral.blueprint.array_spec     = string16 Type ++ uint32 Length
astral.blueprint.map_spec       = string16 KeyType ++ string16 ValueType
astral.blueprint.ptr_spec       = string16 Type
astral.blueprint.object_spec    = (empty payload)
```

`RuntimeRecord` is a record whose `FIELDS` came off the wire instead of a class body; values
live in a dict rather than slots. **It shares the codec with declared records** — there is no
second walker, no "unbound carrier" hazard, and no runtime container slow path, because a
schema-driven decoder constructs each element from its Spec.

Note the limit this operates under: **there is no way to fetch a schema from a node.**
`objects.blueprints` returns names only (a `string8` stream terminated by `eos`, ~180 names
live) and there is no `objects.get_blueprint` on the live registry. Runtime blueprints are
therefore useful for types *the SDK itself* defines and pushes, and for a peer that hands one
over in band — not for learning the node's types. The SDK must carry its own schema for
everything it wants to decode.

---

# 3. The async transport and session

## 3.1 The two seams

There are exactly two ABCs, and the split is forced by the WebSocket JSON subprotocol, which
is message-oriented and has no byte stream underneath it.

```python
class Transport(Protocol):                    # a byte stream
    endpoint: str                             # "tcp:127.0.0.1:8625"
    async def readexactly(self, n: int) -> bytes: ...
    async def read(self, n: int = -1) -> bytes: ...   # b"" == EOF
    def write(self, data: bytes) -> None: ...          # sync, non-blocking, order-preserving
    async def drain(self) -> None: ...
    def write_eof(self) -> None: ...
    async def aclose(self) -> None: ...                # idempotent

class Channel(Protocol):                      # an object stream
    async def receive(self) -> Object: ...     # raises EOFError at clean EOF
    async def send(self, obj: Object) -> None: ...
    def __aiter__(self) -> AsyncIterator[Object]: ...
    @property
    def saw_eos(self) -> bool: ...
    def detach(self) -> Transport: ...         # raises unless framing is byte-exact
    async def aclose(self) -> None: ...
```

| Implementation | Kind | Notes |
|---|---|---|
| `StreamTransport` | Transport | `asyncio.open_connection` / `open_unix_connection`. Covers `tcp:` and `unix:`. |
| `MemTransport` | Transport | In-process duplex pair. Test-only; **not** wire-compatible with Go's `memconn`, so `memu:`/`memb:` endpoints are not dialable. |
| `WebSocketByteTransport` | Transport | `astral.binary.v1` subprotocol; WS binary frames concatenate into one byte stream. |
| `BinaryChannel` | Channel | `string8(type) ++ bytes32(payload)`. The only channel where `detach()` is legal. |
| `JSONLinesChannel` | Channel | One `{"Type":…,"Object":…}` per newline. |
| `TextChannel` | Channel | One `#[type]<sep><body>` per newline; `base64` and `render` are output-only variants. |
| `CanonicalChannel` | Channel | `Stamp ++ string8(type) ++ payload`, no length; latches on first error. |
| `WebSocketJSONChannel` | Channel | `astral.json.v1`; one envelope per WS **text** frame. Binary frames are dropped. |
| `HTTPChannel` | Channel | Response-only, JSON lines. |

`detach()` raises on `JSONLinesChannel`, `TextChannel`, `WebSocketJSONChannel` and
`HTTPChannel`, because a line-oriented receiver may hold a partial line. The protocol never
needs it there: the apphost handshake is **always binary**, on every transport.

A session exposes `supports_raw_stream: bool` — `True` for binary IPC and `astral.binary.v1`
WS, `False` for `astral.json.v1` WS and HTTP. RAW-mode ops (`objects.read` is the only one)
raise `TransportUnsupported` on a session that cannot carry raw bytes, rather than silently
returning something else.

## 3.2 The invariant that shapes everything: no buffering above the reader

On `query_accepted_msg` the connection **stops being a message channel and becomes the
query's raw bidirectional bytestream**. There is no apphost framing after that byte. If the
framing layer read ahead into a buffer of its own, the first bytes of the raw stream would be
stranded in it.

> **Rule 1. The `Channel` must never hold its own read buffer. Every framing read goes
> through the same `asyncio.StreamReader` the raw stream will subsequently use.**

`StreamReader` does buffer, but it is the *same* buffer before and after, so nothing is lost.
`detach()` is therefore a no-op handover of the identical `Transport` object. This is why
astral-go's `streams.ContextReader` (which runs reads in a goroutine and stashes late bytes)
must **not** be ported: porting it would reintroduce exactly the hazard this rule forbids, to
solve a problem — uncancellable reads — that asyncio does not have.

> **Rule 2. Serialise each object into a single `bytes` and issue exactly one
> `writer.write(frame)`, then `await writer.drain()`.**

astral-go needs `channel.WithLockedWrites` (a mutex) because its binary sender issues three
separate `Write` calls. `StreamWriter.write()` is synchronous and appends to the transport
buffer in call order, so single-call frames cannot interleave and **cancellation cannot land
mid-frame** — only `drain()` is cancellable, and by then the frame is committed. No write
lock is needed anywhere in the SDK. (Note the server does *not* do this for IPC guests, which
is astrald bug D-12.)

## 3.3 Endpoint strings

`"<proto>:<addr>"`, split on the **first** colon only, so `tcp:127.0.0.1:8625` is proto `tcp`
and addr `127.0.0.1:8625`. Supported protos: `tcp`, `unix`, `ws`, `wss`, `http`, `https`.
`memu`/`memb` are recognised and **rejected with a clear error**; they are a Go-only
in-process transport.

`~/` in a unix path is expanded **on both dial and listen**. astral-go expands it on listen
only, so a Go client configured with the documented default `unix:~/.apphost.sock` fails to
dial. We expand on both and document the divergence.

Defaults, matching astral-go and the legacy SDK:

```
ASTRAL_ENDPOINT / ASTRALD_ENDPOINT            endpoint override
ASTRALD_APPHOST_TOKEN / ASTRALD_TOKEN /
  ASTRAL_AUTH_TOKEN / ASTRAL_TOKEN            auth token, first non-empty wins
default endpoint: unix:~/.apphost.sock if the socket exists, else tcp:127.0.0.1:8625
```

The unix socket is preferred because it is cheaper and because the node's TCP listener is the
one that wedges (§3.9).

## 3.4 The apphost session, implemented once

`session.py` holds the entire state machine. Binary IPC, WS-binary, WS-JSON and HTTP differ
**only** in which `Channel` implementation `_open_channel()` returns. This was the single
best structural decision in the legacy SDK and it carries over unchanged.

```
connect
  └─ host speaks first, unconditionally: mod.apphost.host_info_msg{Identity, Alias}
     (on a register-handler dial-back there is NO handshake — the first frame is
      handle_query_msg. That listener path reads the first frame directly.)
  └─ optional: guest -> auth_token_msg{Token}
                host -> auth_success_msg{GuestID} | error_msg{auth_failed}
  └─ exactly one of:
       route_query_msg      -> query_accepted_msg  (POINT OF NO RETURN: raw stream)
                             | query_rejected_msg{Code uint8}
                             | error_msg{Code string8}
       register_service_msg -> ack | error_msg{denied}      (stays a message channel)
       attach_query_msg     -> ack | error_msg{route_not_found}  (becomes raw stream)
```

Anonymous guests (no token) may route queries when the node allows it (default on), have the
**Network zone bit stripped server-side** regardless of what they send, and **cannot register
a service or a handler** — even registering the zero identity returns `denied`.

The docs say the guest sends "exactly one of" those messages. That is false on the failure
paths: after `error_msg{route_not_found}` or `query_rejected_msg` the connection is still a
message channel and a second `route_query_msg` is served normally. Only `query_accepted_msg`
is terminal. **We nevertheless close on every failure**, matching astral-go's client, because
reuse is unexercised by any reference implementation and buys nothing.

Client-side defaulting: `Caller` defaults to the session `GuestID` (`None` for an anonymous
session, which encodes as the single `0x00` nil flag); `Target` defaults to the session
`HostID`.

Two anonymous encodings exist and mean the same thing: a nil `*Identity` is `0x00`, and the
`anyone` identity is `0x01` + 33 zero bytes. **Send the nil form for an absent/anonymous
`Caller`; send an explicit identity for `Target`. Accept both on receive.**

Error mapping is exhaustive and lives in one table:

| Wire | Exception |
|---|---|
| `query_rejected_msg{Code}` | `QueryRejected(code)` |
| `error_msg{route_not_found}` | `RouteNotFound` |
| `error_msg{timeout}` | `QueryTimeout` |
| `error_msg{canceled}` | `QueryCanceled` |
| `error_msg{denied}` | `Denied` |
| `error_msg{auth_failed}` | `AuthFailed` |
| `error_msg{target_not_allowed}` | `TargetNotAllowed` |
| `error_msg{protocol_error}` | `ProtocolError` |
| `error_msg{internal_error}` | `InternalError` |
| dial failure | `NodeUnavailable` — the retry key; the query was never sent, so retry is safe |
| in-stream `error_message` object | `RemoteError(msg)` — a **different** channel, never merged with `error_msg` |

Reject codes: `0` success, `1` rejected (default), `2` invalid query, `3` canceled,
`4` internal error, `≥5` op-specific. `RejectWithCode(0)` is a programming error and raises.

## 3.5 Cancellation

| Concern | asyncio primitive |
|---|---|
| Structured lifetime of every task the SDK spawns | `asyncio.TaskGroup` |
| Per-operation deadline | `async with asyncio.timeout(secs)` |
| One-shot reply (`regRequest.done`, `IncomingQuery.response`) | `asyncio.Future` |
| Inbound query fan-out to the app | `asyncio.Queue(maxsize=…)` |
| Registrar ready gate | `asyncio.Event`, **replaced with a fresh object** on disconnect, never `.clear()`ed, so a waiter holding the old Event is not resurrected by a later reconnect |
| Bounded concurrent connections | `asyncio.Semaphore` |
| Best-effort cancel during teardown | `asyncio.shield` |
| Accept loop | `asyncio.start_server` / `start_unix_server` + one task per connection in a `TaskGroup` |
| Byte pump (raw join, tests) | two `create_task(_copy(a, b))` in one `TaskGroup`; first EOF or error tears down both |
| Reconnect backoff | `await asyncio.sleep(d)` in a loop, `d = min(d*2, 30)`, reset to 1 on success |
| Idempotent close | a plain `bool` guard (atomic within one loop iteration) plus `asyncio.Lock` only where an `await` sits inside the critical section |

Everything in astral-go's `sig/` that pairs an operation with `ctx.Done()` —
`sig.Send/Recv/RecvOk/RecvErr/Context/On/OnCtx` — **disappears**; `await` is natively
cancellable. `sig.Map/Set/Value` are thread-safety wrappers around a single-threaded event
loop's job and become plain `dict`/`set`/attributes. `streams.ContextReader` and
`streams.AsyncWriter` are deleted (§3.2). `channel.Switch`'s reflection dispatcher becomes a
`match` on the decoded type name.

**Cancel semantics for an in-flight query.** On `CancelledError` between sending
`route_query_msg` and receiving the response, the SDK makes a shielded best-effort attempt to
route `apphost.cancel?id=<nonce>` **on a fresh connection with its own 2 s timeout**, then
re-raises. astral-go's equivalent dials with the *already-cancelled* context, so its cancel
query is never sent; that defect is not inherited.

```python
try:
    resp = await channel.receive()
except asyncio.CancelledError:
    with contextlib.suppress(Exception):
        await asyncio.shield(self._cancel_query(nonce, timeout=2.0))
    raise
```

`Stream.aclose()` and `Client.aclose()` are **idempotent and never raise**; they cancel owned
tasks, await them, and close transports. `Client` and `Stream` are both async context
managers, and the SDK's own examples and CLI always use `async with`. `__del__`-based cleanup
is explicitly insufficient (§3.9) and is not relied upon anywhere.

## 3.6 Timeouts

Every public async method takes `timeout: float | None`. Named defaults, all overridable on
`Client`, all surfaced as module constants because astrald's are undocumented:

```
CONNECT_TIMEOUT        =  5.0   dial + host_info_msg
HANDSHAKE_TIMEOUT      =  5.0   auth exchange
QUERY_TIMEOUT          = 60.0   route_query_msg -> accepted/rejected; mirrors astrald's
                                undocumented maxQueryTimeout. astral-go's apphost client has
                                NO timeout at all; an outbound query can hang forever.
STREAM_IDLE_TIMEOUT    = None   between objects on an accepted stream; None for follow-mode
CANCEL_TIMEOUT         =  2.0   the shielded apphost.cancel dial
ATTACH_TIMEOUT         =  5.0   server-side deadline for attach_query after incoming_query
ACCEPT_TIMEOUT         =  5.0   server-side deadline for an op to Accept or Reject
FIRST_FRAME_TIMEOUT    =  5.0   our listener waiting for handle_query_msg on a dialed-in conn
BACKOFF_MIN/MAX/FACTOR = 1.0 / 30.0 / 2.0
```

## 3.7 Concurrent multiplexing

**There is none on the IPC leg, by design.** One connection carries at most one accepted
query; after acceptance the socket *is* that query's bytestream. Concurrency means many
connections, and the SDK provides it by opening one per query from a pool.

```python
class Client:
    max_concurrency: int = 8       # asyncio.Semaphore
```

Every `query()` acquires the semaphore before dialing and releases it when the `Stream`
closes. Long-lived streams (`apphost.bind`, `register_handler`'s bind channel, any
`follow=true` op, `objects.register_*`, `log.listen`) hold their permit for their lifetime,
so they are opened through a **separate, unbounded lane** (`Client._open_persistent`) that
does not consume the query budget, and each one is individually tracked for shutdown.

## 3.8 Clean shutdown

`Client` owns: a `set[Stream]` of live streams, a `TaskGroup` for serving tasks, and the
semaphore. `aclose()` — also reached by `async with` exit —

1. stops accepting new work (a `_closing` flag makes `query()` raise `ClientClosed`),
2. cancels the serving `TaskGroup` and awaits it,
3. closes every live `Stream` (which closes its transport),
4. closes the registrar's bind channel last, so the node's crash-safe deregistration fires
   with the handlers already torn down.

Exceptions during teardown are collected and re-raised as an `ExceptionGroup` only if step 1
did not already have a pending exception.

## 3.9 The node's 32-worker pool is a first-class constraint

astrald's apphost module runs `Workers: 32` (default) pulling from an **unbuffered** channel,
with `NewGuest(conn).Serve(ctx)` run synchronously per connection. Therefore:

- the node serves **at most 32 concurrent apphost connections across all local apps**;
- when saturated, new connections are accepted by the OS and **never handshaked** — the
  client sees TCP connect succeed and then hangs waiting for `host_info_msg`;
- a leaked or never-closed stream permanently burns one worker.

This is not theoretical. It was verified on the live node during this session: 32 sockets sit
in `CLOSE-WAIT` on `127.0.0.1:8625` and the node no longer answers. Consequences that are
binding on the SDK:

1. `max_concurrency` defaults to **8**, well under 32, and is documented as a shared-resource
   budget rather than a performance knob.
2. Every stream is an async context manager and closes deterministically. There is no
   `__del__` fallback.
3. `CONNECT_TIMEOUT` applies to reading `host_info_msg`, not merely to the TCP connect, so a
   saturated node surfaces as `NodeUnavailable` in 5 s rather than an infinite hang.
4. `NodeUnavailable` is the only error the retry decorator retries, and it retries with
   backoff, never in a tight loop.
5. The unix socket is preferred by default.

## 3.10 Streaming termination

`eos` is a **convention emitted by the op handler**, not a transport signal, and it is
**per-op**: live, `.spec` sends 118 objects then `eos`; `apphost.whoami` sends one `identity`
and closes with no `eos`; `dir.alias_map` sends one map and closes. A consumer must therefore
terminate on **`eos` or EOF**, and must be able to tell which happened —
`Stream.terminated_by ∈ {"eos", "eof"}`. Never block waiting for `eos`.

`user.sync_assets` is a third shape: zero or more `mod.user.op_update` objects, then a **bare
`uint64`** (the next height) and **no `eos`**. Anything that calls `collect()` on it hangs
forever. Its client method is hand-written and returns `(updates, next_height)`.

---

# 4. The client façade and Stream

## 4.1 Client

```python
async def connect(endpoint: str | None = None, *, token: str | None = None,
                  max_concurrency: int = 8, **timeouts) -> Client

class Client:
    host_id: Identity
    host_alias: str
    guest_id: Identity | None          # None when anonymous

    async def query(self, qs: str, *, target: Identity | str | None = None,
                    caller: Identity | None = None, zone: Zone = Zone.ALL,
                    filters: Sequence[str] = (), fmt_in: str = "bin",
                    fmt_out: str = "bin", timeout: float | None = None) -> Stream
    async def call(self, qs, **kw) -> list[Object]      # drain to eos/EOF, raise RemoteError
    async def call_one(self, qs, **kw) -> Object        # exactly one; extra objects raise
    async def call_raw(self, qs, **kw) -> bytes         # RAW mode; objects.read only
    def stream(self, qs, **kw) -> AsyncContextManager[Stream]
    async def serve(self, identity: Identity, handler: Handler, *,
                    mode: Literal["handler", "service"] = "handler") -> Service
    async def aclose(self) -> None
```

`target` accepts an `Identity` or a `str`. A 66-hex string is parsed locally; anything else is
resolved through `dir.resolve` **before** the query is sent, because the apphost `Target`
field is an identity, not a name. This mirrors astral-go's `ResolveIdentity`.

`call` and `call_one` are thin wrappers over `stream`; there is one implementation of the
query path.

Module clients attach as lazily-constructed, cached properties: `client.dir`, `client.objects`,
`client.tree`, … Laziness is a construction detail only — **wire-type registration is eager**
(`astral/api/__init__.py` imports every module at import time), so whether an object is
decodable never depends on which property someone touched. That was a real latent bug in the
legacy SDK.

## 4.2 Stream

```python
class Stream:
    query: Query
    outbound: bool
    local_id: Identity
    remote_id: Identity
    terminated_by: Literal["eos", "eof"] | None

    def __aiter__(self)                       -> AsyncIterator[Object]
    def raw_objects(self)                     -> AsyncIterator[Object]
    def follow(self)                          -> AsyncIterator[tuple[Object, bool]]
    def snapshot(self)                        -> AsyncIterator[Object]
    def live(self)                            -> AsyncIterator[Object]
    async def collect(self)                   -> list[Object]
    async def value(self)                     -> Object
    async def first(self)                     -> Object | None

    async def send(self, obj: Object)         -> None
    async def send_eos(self)                  -> None
    async def send_bytes(self, data: bytes)   -> None
    async def read_bytes(self, n: int = -1)   -> bytes
    async def write_eof(self)                 -> None

    async def cancel(self)                    -> None   # apphost.cancel on a fresh session
    async def aclose(self)                    -> None
    async def __aenter__/__aexit__
```

`__aiter__` stops at the first `eos` or at EOF and **raises `RemoteError` when it decodes an
`error_message` object**. This inverts the legacy default deliberately: silently yielding an
error object is how a failed pipeline stage injects a wrong-typed object downstream. Code
that wants to see errors as data uses `raw_objects()`, which yields everything and raises
nothing. The CLI uses `raw_objects()`.

`follow()` is the **primitive**; `snapshot()` and `live()` are three-line wrappers over it.
Follow-mode ops (`tree.get?follow=true`, `services.discover?follow=true`,
`objects.scan?follow=true`) send an `eos` that is a **snapshot/live separator, not a
terminator** — the channel stays open. Conflating it with `__aiter__` truncates or deadlocks.
`follow()` yields `(obj, live)` pairs so the boundary is visible to the caller; the legacy
`follow()` swallowed it entirely. Ops whose `follow` flag changes the eos semantics also get
two module-client methods (`discover` / `discover_follow`) rather than a boolean that
silently changes the return type.

`value()` is the RR helper: read one object, then read again and require EOF or `eos`.
`collect()` is the ST helper. Neither is ever used on `user.sync_assets` (§3.10).

## 4.3 Inbound serving — register-handler is primary

The node dials **us**. This is what astral-go's `lib/apps` implements, it survives reconnects,
it needs no per-query attach round trip, it supports many handlers under one bind, and
`asyncio.start_server` / `start_unix_server` fits it exactly.

```
1. Bind a local listener (unix by default, tcp on request) and pick a random Nonce token.
2. START THE ACCEPT LOOP FIRST. Registering before listening can deadlock, because a
   registration hook's own query may be routed straight back into a listener that is not up.
3. Open apphost.bind -> expect ack. Hold this channel open; it scopes handler lifetime.
4. Query apphost.register_handler?endpoint=<proto:addr>&token=<nonce> -> ack. Local-only.
5. Send mod.apphost.bind_msg{Token} on the bind channel — one per handler token, repeatable.
6. Run post-registration hooks (objects.register_searcher / _describer / _finder, …).
7. Per inbound query the node DIALS our endpoint and sends, as the FIRST FRAME and with NO
   handshake: mod.apphost.handle_query_msg{IPCToken, ID, Caller, Target, Query}.
8. Validate IPCToken. Mismatch -> error_msg{denied} + close. Wrong first type ->
   error_msg{protocol_error} + close. Neither kills the listener.
9. Answer exactly once: ack (accept; the socket becomes the response stream)
                      | query_rejected_msg{Code} | error_msg{route_not_found} (skip) | close.
10. On disconnect, reconnect with exponential backoff and re-run 3–6.
```

**Concurrency correction.** astral-go's accept loop is serial: it accepts one connection,
blocks on its first frame, then blocks on routing (up to the 5 s Accept/Reject deadline)
before accepting the next, so one slow dialer stalls every inbound query. We accept in a
loop and handle each connection in **its own task under a `TaskGroup`**, with a
`FIRST_FRAME_TIMEOUT`.

**Write-ordering correction.** astral-go wraps the connection in a `lockableWriteCloser` and
holds the lock until the `ack` is written, so the op handler cannot emit response bytes
first. We achieve the same invariant more simply: **the handler is not given the writer at
all until the `ack` frame has been written.** `PendingQuery.accept()` writes `ack`, *then*
returns the `Stream`.

```python
class Handler(Protocol):
    async def __call__(self, q: PendingQuery) -> None: ...

class PendingQuery:
    query: Query
    async def accept(self) -> Stream          # writes ack, THEN yields the stream
    async def reject(self, code: int = 1) -> None
    async def skip(self) -> None              # error_msg{route_not_found}
    async def aclose(self) -> None            # close with no response
```

An op dispatch table sits on top: `Service.mount("objects.search", coro)` parses the query
string, coerces parameters from their text forms using the op's declared spec, and calls the
coroutine. That is what makes `objects.register_searcher` work (§4.6).

## 4.4 Inbound serving — register-service is shipped but gated

`register_service_msg` / `incoming_query_msg` / `attach_query_msg` / `reject_incoming_msg` is
the WebSocket design. astral-go implements **neither side** of it; the only reference is
`apphost-js`.

It ships behind `mode="service"` and is documented as **experimental on IPC**, for two
reasons found in the astrald source: the IPC worker closes the guest connection
unconditionally after `Guest.Serve` returns, whereas the WS path guards on a `donated` flag —
so a donated responder stream over IPC looks like it is closed immediately; and the IPC
guest channel is created **without** locked writes while the WS one is not, so concurrent
`incoming_query_msg` pushes from arbitrary routing goroutines can interleave a frame's three
writes. Over WebSocket the path is sound and is the only inbound option a browser has.

Semantics when enabled: registration keeps the connection as a message channel; each
`incoming_query_msg` must be answered within 5 s by either opening a **fresh** connection,
completing the handshake (**skipping auth** — the unguessable `QueryID` is the pairing
token), sending `attach_query_msg{QueryID}` and awaiting `ack`; or by sending
`reject_incoming_msg{QueryID, Code}` on the **registration** connection. Ignoring it yields
`route_not_found` for the caller. `IncomingQuery.accept()`/`reject()` are one-shot.

## 4.5 The legacy stubs, settled

No half-built stub is inherited. Each of the twelve is either fully specified or explicitly
dropped with a reason.

| Legacy stub | Decision |
|---|---|
| `apphost.register_handler` dial-back listener ("this SDK does not yet provide that listener") | **SPECIFY FULLY.** §4.3. It is the primary inbound path. |
| `objects.register_searcher` / `_describer` / `_finder` "keep the stream open, the node proxies calls back" | **SPECIFY FULLY, with a corrected model.** §4.6. The legacy model was wrong. |
| `Registration.unregister()` closing the socket as a control-flow device | **REPLACED** by task cancellation and `Service.aclose()`. |
| `objects.echo`'s dead `if not supports_serving: pass` branch | **DROPPED.** `echo` is a plain BD op with no serving involvement. |
| `nodes.migrate_session` negotiated mode (`ready/switched/resume/done`) | **DROPPED in v1.** Tier 3; requires two live nodes and an astrald-only signal state machine that no client reference implements and that cannot be verified in this environment. `start=true` (single `ack`) ships. Reopen when a second node exists. |
| `nat.node_punch`, `nat.node_consume_hole` responder | **DROPPED in v1.** Both require a local UDP hole-punching implementation (astral-go's `nat.Puncher`), which is a transport concern outside the SDK's stated scope. `nat.punch` (node-driven), `nat.list_holes` and `nat.set_enabled` ship. |
| HTTP transport serving | **DROPPED permanently.** astrald exposes no inbound path over HTTP. HTTP is query-only. |
| HTTP silently dropping `caller`, `zone`, `filters` | **FIXED:** passing any of them to an HTTP session raises `TransportUnsupported`. Silently changing semantics is worse than failing. |
| WebSocket force-injecting `in=json&out=json` into every query string | **FIXED:** injected only for `astral.json.v1` and only when the caller did not specify `in`/`out`. |
| `mod.apphost.register_handler_msg` | **DROPPED.** Dead on the wire: astral-go ships the type, astrald has an `onRegisterHandlerMsg` method, and `Guest.Serve`'s dispatch switch never routes to it. Register-handler is an op. |
| `mod.apphost.ping_msg` | **DROPPED as a keepalive.** Registered for decode completeness only, never sent: the live node answers `error_msg{protocol_error}` and closes. |
| `objects.spec` / `objects.type_spec` / `objects.field_spec` | **DROPPED.** The op does not exist — no `op_spec.go` in astrald's objects module and absent from the live 118-op registry. `objects.field_spec` was an invented type name. Replaced by `shell.spec` → `routing.op_spec`, which ships as `client.shell.spec()`. |
| Text encoding send-only, no parser | **SPECIFY FULLY.** A parser is required for `in=text`, for CLI typed arguments, and for query-string parameter values. |

## 4.6 The corrected `objects.register_*` model

The legacy SDK documented "the node proxies `objects.search` calls back over this same
channel; keep the stream open or the registration drops". That is contradicted by
astral-go's own client, which opens the channel, expects an `ack`, and **closes it**.

The real model, from `lib/apps/object_searcher.go`:

1. The app serves inbound queries on its **own identity** (§4.3).
2. It mounts scoped ops on itself: `objects.search` (arg `q`), `objects.describe` (arg `id`),
   `objects.find` (arg `id`).
3. It calls `objects.register_searcher` / `_describer` / `_finder`, reads the `ack`, and
   **closes the channel**. Registration is not channel-scoped.
4. Registration is re-run as a **post-connect hook** by the registrar after every reconnect,
   because the node forgets it on disconnect.
5. On a search the node sends an ordinary query to the app's identity. The app parses the
   search string with the `search_query` grammar, streams `mod.objects.search_result`
   objects, then `eos`. Describers stream `mod.objects.describe_result`; finders stream
   `identity` objects.
6. The caller identity and the zone are **not** propagated to the op.

So there is no serving loop to build — there is an RR call plus an op mounted on the app's own
handler. `SearcherService`, `DescriberService` and `FinderService` are sugar that does both.

## 4.7 Op-mode → façade mapping

The five shapes, and the single generic helper each maps onto. This is the only place op
shape is decided; it is a per-op contract stated in that op's documentation and is **not
discoverable from the wire**, so every module-client method declares its own shape and no
code ever infers one.

| Mode | Shape | Helper | Termination |
|---|---|---|---|
| **RR** | args in the query string; exactly one result object or `error_message`; usually no `eos` | `_rr()` → `Stream.value()` | one object then EOF |
| **ST** | zero or more results, terminated by `eos` and/or EOF | `_st()` → `Stream.collect()` / `__aiter__` | `eos` **or** EOF |
| **ST+follow** | as ST, but the first `eos` is the snapshot/live separator | `_st_follow()` → `Stream.follow()` | never, until closed |
| **WA** | client sends objects on the channel body; server answers one per input | `_wa()` | client `eos`, then server `eos`/EOF |
| **BD** | long-lived, caller drives both directions | `_bd()` → raw `Stream` | caller-controlled |
| **RAW** | response body is unframed bytes | `_raw()` → `Stream.read_bytes()` | EOF |

`objects.read` is the only RAW op. Its response is not a framed object channel at all, which
is why "every accepted query yields objects" must never be assumed.

The single most common way to get an op wrong is passing channel-body input as a query
argument. The confirmed body-input ops: `tree.set` (batch form), `crypto.public_key`,
`crypto.sign_hash`, `crypto.sign_text`, `crypto.verify_hash_signature`,
`crypto.verify_text_signature`, `auth.sign_contract`, `apphost.sign_app_contract`,
`user.accept_contract`, `user.accept_membership`, `objects.store`, `objects.push`,
`objects.create`, `objects.register_blueprint`, and the streamed-id forms of
`objects.contains` / `objects.delete` / `objects.load` / `objects.probe`. A query argument on
`crypto.verify_*` **silently never verifies**.

---

# 5. Module clients

## 5.1 The pattern

One class per module in `astral/api/<module>.py`, holding a reference to the `Client`. Every
op is an `async def` whose body is a single call to one of the six helpers in §4.7, plus
argument marshalling. No op has a hand-written transport path.

```python
class Dir:
    def __init__(self, client: Client) -> None:
        self._c = client

    async def alias_map(self, **kw) -> AliasMap:                    # RR
        return await self._c.call_one("dir.alias_map", **kw)

    async def resolve(self, name: str, **kw) -> Identity:           # RR
        return await self._c.call_one(qs("dir.resolve", name=name), **kw)

    async def filters(self, **kw) -> list[str]:                     # ST
        return [str(o) for o in await self._c.call("dir.filters", **kw)]
```

Attachment: a cached property on `Client`, built lazily, registered eagerly.

```python
class Client:
    @cached_property
    def dir(self) -> Dir: return Dir(self)
```

Rules every module client obeys:

1. **Argument names are the server's field names snake-cased** (`SessionID` → `session_id`,
   `ObjectID` → `object_id`). Matching is **case-sensitive** and unknown keys are **silently
   dropped**, so a capitalised key does nothing at all. astral-go ships two bugs of exactly
   this kind (`apphost.new_app_contract` sending `ID`/`Duration`); we send lowercase always.
2. **Parameter values use the bare payload half of the text encoding** — no `#[type]` header.
   The parameter's type comes from the op's declaration, so it never travels.
   `querystring.encode_param(spec, value)` is the single implementation.
3. **Query strings are built with sorted keys** (matching Go's `url.Values.Encode()`), so
   fixtures are reproducible and byte-identical to the reference client.
4. **The 255-byte query-string cap is advice, not a wire limit.** `RouteQueryMsg.Query` is a
   `string16`. The SDK warns above 255 and errors above 65 535. The legacy hard-capped at 255
   and rejected legitimate queries client-side.
5. **Send `scheme` only when the caller asks**, so the server defaults stand (`bip137` for
   text, `asn1` for hashes).
6. **Type names are module-prefixed (`mod.dir.alias_map`); op names are not (`dir.alias_map`).**
   `mod.` is never part of an op name. Exceptions to the prefix rule that must be spelled
   literally: `apphost.access_token`, `services.update`, `objects.search_query`,
   `objects.query_tag`, `nat.hole`, `nat.endpoint`, `bip137sig.entropy`, `bip137sig.seed`,
   and the plural `mod.users.swarm_member` / `mod.users.created_user_info` alongside the
   singular `mod.user.*`.
7. **Never port an astral-go client bug.** The known set: `dir.apply_filters` queries
   `dir.set_alias`; `objects.new_mem` sends `size` as an int64 where the op wants a size
   string; `objects.read` hardcodes `zone=dvn`; `objects.register_blueprint` and
   `objects.store` never send the terminating `eos`; `tree.Node.Create` never reads its
   response, leaving an `ack` on the wire.
8. **`mod.user.op_update` is defined only in astrald**, not in astral-go's `api/user`. The
   SDK declares it itself.

## 5.2 Crypto and the folded secp256k1

`api/secp256k1` is one op (`secp256k1.new` → `mod.crypto.private_key`) plus four **pure local
helpers**. An `astral.Identity` *is* a compressed secp256k1 public key, so identity ↔ pubkey
conversion is a re-tagging with no curve math.

| Helper | Needs curve math | Ships where |
|---|---|---|
| `identity_to_public_key(id)` | no | `crypto`, always available |
| `public_key_to_identity(pk)` | no | `crypto`, always available |
| `new_key()` → `secp256k1.new` op | no (the node does it) | `crypto`, always available |
| `generate_key_local()` | **yes** | `crypto`, requires the `secp256k1` extra |
| `public_key_of(priv)` | **yes** | `crypto`, requires the `secp256k1` extra |

Without the extra, the curve-dependent helpers raise `FeatureUnavailable` with a message
naming the extra. **The SDK never validates that a 33-byte identity is a point on the curve**
— astral-go's `Identity.ReadFrom` does, and we deliberately diverge: validation would make the
core depend on a curve library for the single most common decode in the protocol. Identities
are 33 opaque bytes; validation is opt-in through the extra.

BIP-39 (`bip39.py`) is pure stdlib: the 2048-word list, `hashlib.sha256` for the checksum,
`hashlib.pbkdf2_hmac("sha512", …, 2048)` for the seed. **BIP-32 derivation is not implemented
locally** — non-hardened child derivation needs point multiplication — so
`bip137sig.derive_key` routes to the node op, which is anonymous-callable.

---

# 6. The `astral-query` CLI

Console script `astral-query`, also reachable as `python -m astral`.

```
astral-query [global options] [target:]<operation> [-param value ...] [-- raw args]
```

## 6.1 Preserved verbatim

The CLI is the only human-facing surface and scripts parse its output. These do not change:

- **`target:operation` prefix form.** A non-66-hex target is resolved through `dir.resolve`
  **before** the query. An explicit `--target` wins over the prefix.
- **Free-form `-param value` pairs** after the operation; leading `-` or `--` both stripped.
- **`objects.read` raw passthrough** — response bytes go to `sys.stdout.buffer`, return 0
  immediately, no object framing.
- **Default output**: one line per object, `f"{type or '<untyped>'}\t{value}"`, bytes decoded
  utf-8 with `errors="replace"` **for display only**.
- **`--json`**: one `{"Type":…,"Object":…}` envelope per line.
- **`error_message` objects go to stderr, set exit 1, and iteration continues**, so a partial
  stream still prints. Implemented with `Stream.raw_objects()`.
- **Exit codes** `0` ok, `1` connect failure / `AstralError` / any `error_message` seen,
  `2` usage.
- **Env precedence** for endpoint and token, exactly as in §3.3.

## 6.2 Added

| Flag | Purpose |
|---|---|
| `--zone dvn` | The legacy could not set it at all |
| `--filters a,b` | Same |
| `--caller <id>` | Same |
| `--in FMT` / `--out FMT` | `bin\|json\|text\|canonical\|base64\|render`. **Validated client-side**: the node silently accepts an unknown `out=` and then produces zero bytes. |
| `--timeout SECS` | A wedged node no longer hangs the CLI forever |
| `--follow` | Prints the snapshot, a `--- live ---` separator on stderr, then live updates |
| `--input FILE` / `--input -` | Channel-body input, one text-encoded object per line, terminated with `eos`. Unlocks `tree.set`, `crypto.verify_*`, `crypto.public_key`, `objects.store/push/create`, `auth.sign_contract`, `user.accept_membership` — a large fraction of the protocol the legacy CLI could not reach. |
| `-p name=#[type]value` | A typed parameter, using the full text encoding |
| `--dump-wire` | Hex frame dump to stderr, replacing the standalone `examples/dump_handshake.py` that duplicated the framing logic by hand |
| `--version` | |
| **exit 3** | `QueryRejected`, with the numeric code on stderr. The legacy printed it through the generic handler and returned 1. |

## 6.3 Sync entry point over an async core

```python
def main(argv: list[str] | None = None) -> int:
    try:
        return asyncio.run(_amain(argv or sys.argv[1:]))
    except KeyboardInterrupt:
        return 130

async def _amain(argv) -> int:
    args = _parse(argv)
    async with await connect(args.endpoint, token=args.token,
                             max_concurrency=1) as client:
        ...
```

One `asyncio.run` at the top, one `async with` on the client, `max_concurrency=1` because the
CLI issues one query (plus at most one `dir.resolve`). `KeyboardInterrupt` maps to 130 and the
`async with` guarantees the connection closes, so Ctrl-C never leaks a node worker.

Argument parsing is fixed: `argparse` with `allow_abbrev=False` for the global options,
`parse_known_args`, then a manual pass over the remainder for `-param value` pairs, with `--`
supported as an explicit terminator. The legacy hand-rolled parser mis-parsed `--endpoint`
appearing *after* the operation and swallowed it as a query parameter.

---

# 7. Testing strategy

Three tiers. **Tiers A and B run with no node and no network and are the gate for every
commit.** Tier C needs a healthy node and is opt-in.

Framework: **stdlib `unittest`**, with `unittest.IsolatedAsyncioTestCase` for async tests.
Justification: it keeps `dependencies = []` true even for development, `python -m unittest
discover` works in any environment, and the legacy suite (4 741 lines) already proved the
approach on this codebase. No pytest, no hypothesis.

## 7.1 Tier A — byte vectors, no node

Golden vectors live in `tests/vectors/` as JSON: `{name, type, value, payload_hex,
canonical_hex, object_id, json, text}`. Every one is round-tripped in both directions and the
bytes compared exactly.

Sources, in order of authority:

1. **The nine literal vectors in astral-docs** (`topics/codec.md` §Canonical Form;
   `topics/binary-encoding.md` slices, arrays, maps, sort order, optionals, presence flags,
   polymorphic fields; `primitive-types/object.md`). These are the only byte vectors the
   entire doc corpus contains, and they cover only `uint8`, `uint16`, `uint32`, `string8` and
   `string16` — and only incidentally, inside composite examples.
2. **Vectors generated from astral-go** and checked in. This is mandatory, not optional: the
   docs contain **no** literal vector for `bool`, `int8..int64`, `uint64`, `float32/64`,
   `string32/64`, `bytes8..64`, `time`, `duration`, `identity`, `nonce64`,
   `object_id.sha256`, `zone`, `ack`, `eos`, `error_message`, `object_type`, `stamp`, the
   untyped blob, any struct, any heterogeneous container, any blueprint, any apphost message,
   or any link-mux frame. Generation is a throwaway Go program run inside the astral-go
   worktree; its output is committed and the program is not.
3. **Live captures** from this session's surveys, committed verbatim as fixtures.

The must-pass set, all verified this session:

```
[]uint32{1,2,0xDEADBEEF}         00000003 01 00000001 01 00000002 01 deadbeef
[2]uint16{1,2}   (no count)      01 0001 01 0002
map[string16]uint8{"ab":2,"hi":1} 00000002 0002 6162 01 02 0002 6869 01 01
map[uint16]uint8 sort order      keys ascend 0001 < 0007 < 0100
[]Object{u32(1), s8("hi")}       00000002 0675696e743332 00000001 07737472696e6738 026869
optional uint16 absent/present   00  /  01 002a
polymorphic uint8=7 / nil        0575696e743807  /  00
nil *Identity / Anyone           00  /  01 + 33 zero bytes
mod.apphost.host_info_msg frame  19 "mod.apphost.host_info_msg" 0000002d 01 <33B> 0a "furry-bolt"
dir.alias_map payload            00000001 000a "furry-bolt" 01 <33B>
canonical uint32(42)             41444330 06 "uint32" 0000002a
Blueprint("t.x", …)              0003742e78 00000002 01 000161 1f"…primitive_spec" 0006"uint32"
                                 01 000162 1c"…object_spec" 0000
BlueprintAlias("t.mode","uint8") 0006742e6d6f6465 00000000 0005 75696e7438
time(1ns) / time(-1ns)           0000000000000001 / ffffffffffffffff
Duration(-1)                     ffffffffffffffff
Float32(1.5) / Float64(1.5)      3fc00000 / 3ff8000000000000
Int8(-1) Int16(-2) Int32(-3)     ff / fffe / fffffffd
bundle{uint8(7), string8("hi")}  00000002 00000007 0575696e743807 0000000b 07737472696e6738026869
empty slice / empty map          00000000 / 00000000
Query{nonce, Anyone, Anyone, s}  8+34+34+4+len  (93 bytes for "dir.alias_map")
Query{nonce, nil, nil, "x"}      15 bytes — nil pointer is NOT Anyone
```

Negative cases, each its own test: presence byte `0x02` raises; an unregistered type tag
raises `StreamCorrupted`; a truncated `string16` raises and assigns nothing; `Array.length >
65536` is rejected at registration; a `Ref`/`Ptr` self-reference is rejected; a two-step
`Ref` cycle is rejected (astral-go stack-overflows here — we must not); field names differing
only in case are rejected; a `uint8` set to 256 raises; `Uint*.from_text("-1")` raises; JSON
marshal of `float("inf")` raises.

Plus the six ObjectID reference vectors of §2.7, and a seeded random round-trip sweep over
every spec kind (`random.Random(0)`, 10 000 cases, no external dependency).

## 7.2 Tier B — in-process mock servers, no node

Two harnesses, both over `MemTransport` **and** over a real loopback `asyncio.start_server`,
so the socket path is exercised too.

- **`MockApphost`** — a scripted server that replays a frame sequence: handshake, optional
  auth, then a table of `query string → [response frames]`. It is built from the live captures
  in the surveys, so a Tier-B pass means the client would have satisfied the real node on
  those exact exchanges. It covers: acceptance and the channel→raw handover; every
  `error_msg` code; `query_rejected_msg`; a stream terminated by `eos`; a stream terminated
  by bare EOF; a follow-mode stream with a separator `eos` followed by live objects;
  `objects.read`'s unframed byte response; half-close (`write_eof` then still reading).
- **`MockDialer`** — the register-handler counterpart: it *dials* the SDK's listener and
  sends `handle_query_msg` as the first frame with no handshake, then asserts the SDK answers
  exactly one of `ack` / `query_rejected_msg` / `error_msg` / close. Covers token mismatch,
  wrong first frame type, the first-frame timeout, and concurrent inbound connections (the
  test that would have caught astral-go's serial accept loop).

**The ambient environment is blanked before any of this runs.** §3.3's fallback is
what an application wants and what a Tier-B test cannot survive: a developer's exported
`ASTRALD_APPHOST_TOKEN` is offered to a mock that has no token, refused, and the test dies
on `AuthFailed` without a node being involved anywhere. `mock_apphost` empties the six
production endpoint and token variables at import — the only hook a stdlib `unittest` run
offers that covers `discover`, one module and one test alike — and a rail in
`test_mock_apphost.py` asserts both that it happened and that every test module calling
`connect` imports it. Tier C keeps its own names (§7.3) and is untouched.

Specific invariant tests that exist because a survey found a hazard:

1. **No stranded bytes at the handover.** The mock sends `query_accepted_msg` and the first
   raw-stream bytes **in the same TCP segment**. The client must see all of them. This pins
   §3.2 Rule 1.
2. **One `write()` per frame.** A `Transport` spy records call boundaries; every frame must be
   exactly one `write`. This pins §3.2 Rule 2.
3. **Cancellation mid-query issues `apphost.cancel` on a fresh connection.** The mock counts
   connections and asserts the cancel query arrives after the first is cancelled. This pins
   the fix for astral-go's broken cancel path.
4. **`aclose()` closes every transport.** A leak detector asserts zero open transports after
   `async with` exit, including on the exception path. This pins the worker-pool discipline.
5. **The semaphore bounds concurrency.** 50 concurrent `query()` calls against a mock that
   counts simultaneous connections must never exceed `max_concurrency`.

## 7.3 Tier C — live node

Gated on `ASTRAL_TEST_ENDPOINT` being set; skipped entirely otherwise, with a message. Before
any test runs, a **health precheck** dials with a 5 s timeout and skips the whole tier if
`host_info_msg` does not arrive — which is exactly the state the node is in right now.

Only the anonymous-safe, read-only op set is targeted:

```
apphost.whoami            dir.alias_map      objects.blueprints     tree.list
apphost.list_tokens       dir.filters        objects.repositories   tree.get (follow=false)
apphost.list_held_objects dir.resolve        objects.new            services.discover (follow=false)
shell.spec                dir.get_alias      objects.get_type       ip.local_addrs
                          dir.apply_filters  objects.echo           ip.public_ip_candidates
                                             objects.scan (follow=false)  ip.default_gateway
                                             objects.search         nodes.links / sessions
crypto.public_key         bip137sig.new_entropy / mnemonic / seed / derive_key
crypto.verify_*_signature user.* (reject code 2 on an unclaimed node — itself a valid assertion)
```

Nothing that mutates state ever runs: no `dir.set_alias`, no `tree.set/delete`, no
`objects.create/store/delete/purge/push/new_mem/register_*`, no `auth.index`, no
`services.sync`, no `apphost.register/bind/register_handler/cancel`, no `user.*` writes, no
`nodes.*` writes, no `nat.punch`.

Tier C runs with `max_concurrency=4`, every test inside `async with`, and a module-level
teardown that asserts zero live streams — because a leaked stream burns a node worker
permanently and thirty-two of them wedge the node for everyone.

Serving tests (`register_handler`, `bind`) require an auth token and therefore run only when
`ASTRAL_TEST_TOKEN` is also set; they register on a throwaway identity and always deregister.

## 7.4 What runs where — summary

| Suite | Node required | Runs on |
|---|---|---|
| Tier A: vectors, codec, ObjectID, blueprints, query strings, text/JSON | **no** | every commit |
| Tier B: transports, channels, session, client, stream, serving, CLI | **no** | every commit |
| Tier C read-only: anonymous smoke tests | **yes** | opt-in, `ASTRAL_TEST_ENDPOINT` |
| Tier C serving: register_handler round trip | **yes, plus a token** | opt-in, `ASTRAL_TEST_TOKEN` |

---

# 8. Python baseline

**`requires-python = ">=3.11"`.**

The legacy claimed 3.8, which has been end-of-life since October 2024. The decision is
between 3.10 and 3.11, and 3.11 wins on two primitives this design depends on structurally:

- **`asyncio.TaskGroup`** (3.11). The serving listener, the registrar, and `Client` shutdown
  are all specified as task groups; first-exception-cancels-siblings is the semantics that
  replaces astral-go's `errgroup`-shaped error channels. `asyncio.gather` is not a substitute:
  it does not cancel siblings on the first failure and leaves orphaned tasks on cancellation,
  which for this SDK means leaked connections and burned node workers (§3.9).
- **`asyncio.timeout()`** (3.11). Every deadline in §3.6 is expressed with it. The 3.10
  alternative, `asyncio.wait_for`, cannot be nested cleanly and does not compose with
  `TaskGroup`.

Both are backportable — `taskgroup` and `async-timeout` exist on PyPI — but adding two
runtime dependencies to avoid a version floor is the wrong trade for an SDK that applications
embed, and it would break `dependencies = []`.

Three further 3.11 features are used and are not merely convenient: `ExceptionGroup` /
`except*` for teardown aggregation, `enum.StrEnum` for channel-format and error-code enums,
and `typing.Self` for `read_payload`. 3.11 is supported until October 2027, and the target
environment already runs 3.12+ (this workstation is on 3.14.4). Nothing in the design needs
3.12.

## 8.1 Dependencies

**`dependencies = []`.** Core, transports, serving and CLI are stdlib-only.

| Candidate dependency | Decision |
|---|---|
| A WebSocket library (`websockets`) | **Not taken.** The client half of RFC 6455 that this SDK needs is small and bounded: an HTTP upgrade with `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` validation, client-masked frames from `os.urandom`, ping/pong/close control frames, and receive-side fragmentation reassembly. **No extensions are offered** (no permessage-deflate), there is no server role, and frame and message sizes are capped. Forcing every embedder to take a dependency for an alternate transport is a worse trade than ~200 well-tested lines. |
| An HTTP client (`httpx`, `aiohttp`) | **Not taken.** The HTTP transport issues one request and reads a newline-delimited JSON body. Writing the request line, the headers and a chunked/`Content-Length` body reader over `asyncio` streams is ~150 lines and adds nothing to the trust surface. |
| A curve library (`coincurve`) | **Taken, as the optional extra `astral-ipc[secp256k1]`, and only for key generation and local signing/verification.** Justification: secp256k1 arithmetic cannot be implemented responsibly in pure Python (constant-time behaviour, point validation), and it is genuinely optional — every op the SDK exposes can be served by the node, and `Identity` handling needs no curve math at all (§5.2). Absent the extra, the affected helpers raise `FeatureUnavailable`; nothing else degrades. |
| A test framework (`pytest`, `hypothesis`) | **Not taken.** `unittest` + a seeded `random` sweep covers the need with zero dev dependencies (§7). |

---

# 9. Risk register

Every unverified wire assumption inherited from the legacy SDK, plus every docs-vs-node and
go-vs-go disagreement the seven surveys found. **R** = risk carried into the rewrite,
**D** = astral-docs bug report, **G** = astral-go / astrald bug report. Each carries the live
probe that settles it. All probes are read-only unless marked.

**Every probe below is blocked until the node is restarted** (§0). Getting a healthy node is
implementation step 0.

## 9.1 Risks that must be settled before the affected module ships

| # | Risk | Resolution taken | Settling probe |
|---|---|---|---|
| R-1 | Legacy decoded `identity` as presence byte + 33 bytes | **Settled: 33 flat bytes.** Live `apphost.whoami` returned a 33-byte payload. Kept as a permanent regression test. | `apphost.whoami` with `out=bin`; assert the frame's `bytes32` length is exactly 33 |
| R-2 | Legacy modelled `*ObjectID` fields as bare `object_id.sha256`, missing the nil flag — four records off by one byte | Modelled as `Ptr("object_id.sha256")` | `objects.scan?repo=main` for any id, then `objects.describe?id=<id>&out=bin`; assert `mod.objects.describe_result` payload begins `01 <33B identity> 01 <40B id>` |
| R-3 | Legacy asserted astral-go flattens embedded structs in **JSON**; source says nested under the type name | Nested in JSON, flattened in binary (§2.5) | `user.info?out=json` on a claimed node, or any `mod.auth.signed_contract`; assert a `"Contract"` key exists |
| R-4 | `nonce64` JSON is unpadded hex in Go, "16-digit" in the docs | Emit unpadded in JSON (Go-compatible), padded in text, accept both on parse | `nodes.sessions?out=json` or `nat.list_holes?out=json`; read an `ID` and check for a leading-zero-stripped value |
| R-5 | Zero `ObjectID` marshals to `""` and `""` fails to parse in Go — asymmetric | We emit `""` and **accept** `""` as the zero ID | `objects.new?type=mod.objects.search_result&out=json`; assert `"ObjectID":""` or `null` |
| R-6 | Zero identity JSON is the literal `"anyone"`; the legacy mapped it to `""` and would crash on `bytes.fromhex("anyone")` | **Settled live**: `apphost.whoami?out=json` → `{"Type":"identity","Object":"anyone"}` | as noted, kept as a regression test |
| R-7 | astral-go's `Any`/`ObjectSpec` nil is `0x00` on the reflection path and `string8("nil")` on the runtime path — **it cannot read its own output** | Write `0x00`, accept both (§2.9) | `objects.blueprints` to find a runtime-blueprint type, then `objects.new?type=<that>&out=bin`; compare against `objects.new?type=err_unexpected_object&out=bin` |
| R-8 | `mod.objects.repository_info.Free` is `Uint64` in Go, documented and exampled as a signed `-1` | Decode as `uint64`; treat `0xFFFF_FFFF_FFFF_FFFF` as "unknown/unbounded" | `objects.repositories?out=bin`; read the 8-byte `Free` |
| R-9 | Presence byte `0x00` inside a value slot: docs say "absent", astral-go rejects | Write `0x01`, accept `0x00` as `None` on read | Send `route_query_msg` with `Filters` count 1 and a `0x00` element byte; expect `error_msg{protocol_error}`, confirming the server is strict |
| R-10 | Query-string cap: docs say 255 bytes, `RouteQueryMsg.Query` is `string16` | Warn at 255, error at 65 535 | Route a 300-byte query string; expect `route_not_found` (it reached routing), not `protocol_error` |
| R-11 | `bip137sig.entropy` / `.seed` layout is source-only | `bytes8` + a length validator (§2.5) | `bip137sig.new_entropy?bits=128&out=bin`; assert payload `10` + 16 bytes |
| R-12 | `mod.ip.ip_address` is `bytes8` with a length-dependent text form; the legacy had two contradictory `_ip_str` helpers | One `bytes8` record, one text function | `ip.local_addrs?out=bin`; assert each payload is `04`+4 or `10`+16 |
| R-13 | `services.update.Info` is an `astral.Bundle` — the legacy treated bundles as opaque | Full `Bundle` record decoding inner objects through the registry | `services.discover?follow=false&out=bin`; decode the `Info` field |
| R-14 | `routing.op_spec` uses plain-Go-`string` fields, i.e. `string32` prefixes | `Primitive("string32")` for `Name`/`Type` | `shell.spec` with `out=bin`; assert the first field is a 4-byte length |
| R-15 | `mod.nodes.node_info` numeric endpoint tags: an unknown tag is a hard decode error | Ship codec-only `tcp`/`tor`/`gateway`/`kcp` endpoints (§0.1) | `nodes.links?out=bin` on a node with a live link |
| R-16 | Attach-query over IPC may be closed by astrald's worker (`donated` flag is only honoured on the WS path) | Register-service shipped **gated**, WS-first (§4.4) | **Requires a token.** Authenticate, `register_service_msg`, route a query to that identity from a second connection, `attach_query_msg`, and check whether the donated socket survives |
| R-17 | Reject-code tables for `nodes` (2–5) and `user` (2/3) are source-only | Codes are surfaced numerically in `QueryRejected`; no semantic mapping is claimed | `user.info` on an unclaimed node → expect code 2 |

## 9.2 astral-docs bug reports

| # | Defect |
|---|---|
| D-1 | Base64 variant is never specified anywhere (`bytes*.md`, `text-encoding.md`, blob). It is `StdEncoding` with `=` padding; URL-safe or raw would break interop silently. |
| D-2 | `time` JSON/text is documented as "ISO 8601"; the implementation emits and parses RFC 3339 only. |
| D-3 | `primitive-types/object_id.sha256.md` omits the leading-`y` stripping that `core-definitions/object-id.md` mandates. Reading only the primitive doc yields a 69-char ID and every comparison fails. |
| D-4 | `nonce64` JSON is documented as a 16-digit hex string; Go emits unpadded hex. |
| D-5 | `codec.md` says only `Canonical` rejects an empty Object Type; `Short` rejects it too. |
| D-6 | Text separators: docs give `:` and ` `; the parser also accepts `=` and `\t`. |
| D-7 | Channel format tokens are undocumented as a set: `bin\|json\|text\|canonical\|base64\|render`. |
| D-8 | `zone` has no `primitive-types/zone.md`, and its JSON form (a **string** `"dvn"`, not a number) is documented nowhere. |
| D-9 | The docs never state which string width a struct field uses. A bare Go `string` field is **`string32`** and a bare `[]byte` field is a **slice of `uint8`**, not `bytesN`. Highest-impact silent-corruption trap in the corpus. |
| D-10 | `topics/astral-ipc.md` writes the acknowledgement type as `astral.ack` in four places; the registered type is `ack`. Same for `eos`. |
| D-11 | Bundle wire format is entirely undocumented, and it **inverts** the type/length order relative to the binary channel. |
| D-12 | `canonical`, `base64` and `render` channel formats are undocumented; `canonical` has genuinely different framing (no length prefix at all). |
| D-13 | "Closing the registration connection unregisters the handler" is wrong: removal is lazy, on the next failed push, so a dead registration lingers and consumes a routing attempt. |
| D-14 | "The guest may then send exactly one of…" is wrong on the failure paths: after `route_not_found` or a rejection the connection is still a message channel. |
| D-15 | Query String is capped at 255 bytes in `query-string.md` while every wire carrier uses a 16-bit prefix. |
| D-16 | `objects.spec` and `objects.type_spec` are documented but do not exist; `objects.field_spec` is an invented type name. |
| D-17 | Capitalised parameter names in five doc files (`tree.delete -Recursive`, `tree.set -Type -Value`, `nat.list_holes -With`, `nat.punch -Target`, `nat.node_consume_hole -Pair -Target`) — matching is case-sensitive and unknown keys are silently dropped, so every one of those shellsession examples is a no-op. |
| D-18 | `dir.set_alias`'s `alias` is documented optional; it is `query:"required"` and removal needs an **empty** `alias=`. |
| D-19 | "required" markers are aspirational throughout; only ten ops have enforced requirements. |
| D-20 | `ip.local_addrs.md` / `ip.public_ip_candidates.md` print `{"Type":"astral.eos"}`; the type is `eos`. |
| D-21 | `bip137sig.derive_key` is documented as returning `crypto.private_key`; the name is `mod.crypto.private_key`. |
| D-22 | `mod.objects.repository_info.Free` is exampled as a signed `-1`; it is `Uint64`. |
| D-23 | `object-stream.md` implies `eos` is universal; it is per-op, and `apphost.whoami` and `dir.alias_map` end at bare EOF. |
| D-24 | An unknown `out=` value is silently accepted and produces zero bytes; no error is reported. |
| D-25 | `query.md` says a Query carries a Zone; the `query` wire type has no Zone field. Zone travels per-hop. |
| D-26 | The endpoint table omits `memu`/`memb`, on which the node listens by default. |
| D-27 | `protocols/auth/types/mod.auth.sudo_action.md` has no counterpart anywhere in astral-go. |
| D-28 | `object-id.md` should name the two ID code paths explicitly (typed canonical vs raw untyped); the ambiguity is what makes astral-go's `ResolveObjectID` unsafe on untyped input. |
| D-29 | `objects.scan?follow=true`'s snapshot half is documented as the stored set with no statement about order, and it does **not** share the plain `objects.scan`'s order. Measured against `furry-bolt`: solo, 30 of 30 scans and 30 of 30 snapshots agreed on one order; with four snapshot-then-scan pairs in flight at once, 4 of 160 pairs disagreed and every divergence was on the snapshot side. A client that compares the two as lists has a flake that only appears under concurrent load. Order is not a property of either answer; the objects are. |
| D-30 | `crypto.sign_text` against a key the node cannot hold has **two** legal outcomes and the docs describe neither. astrald builds the text signer before reading the body, so it answers and closes; whether the caller sees the node's `error_message` or the reset depends on which reaches the socket first. Measured: solo, every attempt resets; with six concurrent attempts, 7 of 72 read the error object cleanly. A client must accept both. |

## 9.3 astral-go / astrald bug reports

| # | Defect |
|---|---|
| G-1 | `ObjectSpec` nil is written two different ways and the runtime codec **cannot read its own output** (§2.9). |
| G-2 | `ResolveObjectID` has no untyped branch, so it returns a wrong ID for a `Blob`. |
| G-3 | `ErrorMessage.UnmarshalJSON` infinitely recurses — a verified stack overflow. |
| G-4 | `Int16/Int32/Int64.UnmarshalText` parse at bit size 8, so any value outside int8 range fails. |
| G-5 | Eight types report the wrong `n` from `WriteTo`/`ReadFrom` (`Uint16..Uint64` report 1; `Query` reports 90 for 93 bytes). |
| G-6 | `String16.ReadFrom` assigns partial data **before** checking the error, so a caller ignoring the error gets a silently truncated string. |
| G-7 | The query-cancel-on-context-cancellation path dials with the already-cancelled context, so `apphost.cancel` is **never sent**. |
| G-8 | `api/dir/client/apply_filters.go` queries `dir.set_alias` — it can mutate an alias. |
| G-9 | `api/apphost/client/new_app_contract.go` sends capitalised arg keys, which are silently dropped. |
| G-10 | `objects.register_blueprint` and `objects.store` clients never send the terminating `eos`. |
| G-11 | `tree.Node.Create` issues `tree.set` and never reads the response, leaving an `ack` on the wire. |
| G-12 | astrald's IPC guest channel is created **without** locked writes while the WS one is not; concurrent `incoming_query_msg` pushes can interleave a frame's three writes. |
| G-13 | **astrald's apphost worker pool wedges.** 32 workers, an unbuffered accept channel, and connections that reach `CLOSE-WAIT` without the server noticing EOF permanently exhaust the pool; new connections are then accepted by the OS and never handshaked. **Observed live this session** (§0, §3.9). |
| G-14 | The inbound handler accept loop is serial: one slow dialer stalls every other inbound query. |
| G-15 | `~/` expansion is listen-only, so a Go client configured with the documented default `unix:~/.apphost.sock` cannot dial it. |
| G-16 | `mod.apphost.register_handler_msg` is registered and has a server method but is unreachable — the dispatch switch never routes to it. |
| G-17 | `mod.apphost.ping_msg` is a registered type with no handler; sending it yields `protocol_error`. |
| G-18 | `OrderedBlueprints()` and `AllBlueprints()` disagree on prototype-vs-alias order. |
| G-19 | `blob` is not registered: `Blob.ObjectType()` is `""` so its `init()`'s `Add` fails and the error is discarded. |
| G-20 | `ObjectID.IsZero()` ignores `Size`, so `{Size:99, Hash:0}` serialises to 40 zero bytes, JSON-marshals to `""`, yet `String()` renders `data1gg…`. |
| G-21 | There is no way to fetch a blueprint's schema from a node: `objects.blueprints` returns names only and `objects.get_blueprint` is absent from the live registry, even though astral-go's docs imply schema learning is possible. |
| G-22 | A two-step mutually-recursive `RefSpec` pair installed directly into the registry still stack-overflows at construction; the depth guard only wraps I/O. |

---

# 10. Implementation order

Each step is independently testable and leaves the tree green. Steps 1–5 need no node and no
event loop; step 0 is a prerequisite for anything in Tier C.

| # | Step | Gate |
|---|---|---|
| 0 | **Get a healthy node.** Ask the user to restart `astrald`; re-run the §9 probes. | `apphost.whoami` answers in <1 s |
| 1 | `errors.py`, `wire.py`, `types.py`, and the Tier-A vector harness. Generate the astral-go vector corpus and commit it. | All nine doc vectors + the generated corpus round-trip |
| 2 | `spec.py`, `record.py`, `registry.py`, `codec/binary.py`, `object.py`, `primitives.py`. | The §7.1 must-pass table, including the map kind and every negative case |
| 3 | `objectid.py`. | The six reference ObjectIDs |
| 4 | `codec/jsoncodec.py`, `codec/text.py`, `querystring.py`. | JSON and text round-trips for every registered type; parameter text forms |
| 5 | `blueprint.py` + `RuntimeRecord`. | The blueprint wire vectors; a runtime record decodes identically to a declared one |
| 6 | `transport/{base,socket,mem}.py`, `channel/binary.py`. | The `MockApphost` framing tests and the two invariant tests of §7.2 |
| 7 | `session.py`, `conn.py`, `context.py`. | Every session path against `MockApphost`, including the handover and all nine error codes |
| 8 | `client.py`, `stream.py`. | Concurrency bound, cancel-on-cancellation, leak detector; first Tier-C smoke test |
| 9 | `api/apphost.py`, `api/dir.py` — the two smallest real modules, and `dir.alias_map` proves the map kind end to end. | Live `dir.alias_map` decodes to a typed `AliasMap` |
| 10 | `serve.py`, `registrar.py`. | `MockDialer` suite; live register-handler round trip when a token is available |

**Step 10's live half of the gate is UNMET in this environment and must not be read as met.**
`register_handler` and `bind` need `ASTRAL_TEST_TOKEN`, which is not set here, so `LiveServiceTest`
skips while the rest of the live tier is green. The whole serving path — `Service`, `Registrar`,
`apphost.register_handler`, `apphost.bind` — therefore has **mock-only** evidence. That is the
subsystem in which five of the six occurrences of the cancelled-teardown defect were found, so
"live tier green" covers everything except the part with the worst history. The skip says so
itself; this says so where the gate is claimed.
| 11 | Remaining Tier 1: `crypto`, `auth`, `services`, `tree`, then `objects` (25 ops, largest). | Live read-only smoke per module |
| 12 | `cli.py`. | Output-format golden tests; all six exit codes |
| 13 | Tier 2: `user`, `bip137sig` + `bip39.py`, `ip`, `exonet` + `endpoints.py`. | `user.sync_assets`'s non-EOS shape is handled |
| 14 | `channel/{jsonl,textchan,canonical}.py`, `transport/{websocket,http}.py`. | Format matrix against a live node: `bin`/`json`/`text`/`canonical` all decode to the same value |
| 15 | Tier 3 gated: `nodes`, `nat` (minus the dropped ops of §4.5). | Import-gated behind an explicit opt-in flag |

---

# 11. Amendments (2026-07-27, after the wire core landed)

The wire core is implemented, reviewed by three adversarial lenses, and committed at `b099baf`.
Implementation raised five objections to this document. Each is resolved below. **These
resolutions are binding and supersede the sections they name.**

## 11.1 Section 2.3, write side — absent container elements (AMENDED, already implemented)

Section 2.3 says "on write emit `0x01`" for a container element. That is unsatisfiable for an
element with no value: there is no payload for the flag to precede. **Amendment: write `0x00` for
an absent element.** This is what astral-go's blueprint-built containers do — `resolveElemType`
hands them a pointer prototype — and it is what makes decode-then-encode byte-exact. Verified:
astral-go reads the SDK's `0000000201000100` and re-emits it identically.

## 11.2 Section 2.2, the bundle row — uniqueness (AMENDED, already implemented)

**Amendment: a bundle's objects are unique by ObjectID, enforced on construction and on decode.**
The design was silent, so astral-go rules: `Bundle.ReadFrom` aborts mid-frame with
`duplicate object` and `Append` refuses a repeat. Because it is enforced on decode it is part of
the wire contract, not an API nicety. Filed against the docs as D-11's extension.

## 11.3 Array spec-zero — which zero is canonical (RESOLVED)

The SDK's array spec-zero holds element zeros where astral-go's holds nil pointers, so a runtime
zero value differs in both JSON (`"Ar":[0,0]` against `[null,null]`) and binary (`01000100`
against `0000`). astral-go reads both. **Resolution: keep the SDK's element zeros.** A zero value
whose elements are absent is not a usable zero value in Python, where there is no nil pointer to
stand in, and the encoding astral-go accepts either way. No code change.

## 11.4 Section 2.9, read and write sides — `nil` in a polymorphic slot (DEFERRED, tracked)

Two genuine defects in this document, both proved against astral-go rather than argued:

- **Read side.** Section 2.9 accepts both `0x00` and `string8("nil")` as absent. But `nil` is a
  *registered object type*, not a private marker, so collapsing its tag to `None` loses a
  distinction astral-go's reflection codec keeps and breaks the byte round trip
  (`036e696c` decodes, then re-encodes as `0x00`).
- **Write side.** For a `RuntimeRecord`, section 2.9's `0x00` in an `Any` slot is bytes **no
  astral-go path can read**: the runtime reader refuses them with
  `stream corrupted: blueprint not found`, and the reflection reader never sees a runtime type.
  The design's rationale — "the form produced by every type the SDK will actually exchange" —
  does not hold for runtime records.

The likely correct shape is to narrow the tolerance and the emission by provenance: a field
decoded through a *runtime blueprint* uses `string8("nil")`, a declared field uses `0x00`.

**Deferred deliberately, not forgotten.** The wire core is green, independently verified and
committed; this path is reached only when decoding a type the SDK was never built against, so no
Tier 1 or Tier 2 module depends on it. Changing the Any/nil rules is exactly the kind of subtle
edit that destabilises a verified core, and it sits inside astral-go's own self-contradiction
(G-1, G-25) where the reference cannot read its own output either. Current behaviour is
implemented as this document originally specified, tested, and pinned by
`test_the_runtime_nil_tag_does_not_survive_a_round_trip` and
`test_an_absent_polymorphic_field_writes_the_documented_zero_byte`, whose docstrings record the
divergence. It is settled before `RuntimeRecord` is relied on in anger — i.e. before any module
decodes an unregistered type in production — and tracked as its own task.

Do not partially apply this amendment while building the transport, session or module layers.

## 11.5 Sections 3.1, 3.2 and 3.7 — the boundary fact belongs to every framing layer (AMENDED, implemented)

Section 3.7 gives the rule that keeps an abandoned read from becoming a forged frame: a read cut
off anywhere but at a frame boundary closes the connection, and the *channel* answers whether it
stranded anything. The rule was written for one framing. There are three.

`Transport` therefore declares `at_frame_boundary`, defaulting to `True` — the honest answer for a
transport that frames nothing — and every layer conjoins the layer below:

| Layer | Answers false when |
|---|---|
| `WebSocketClient` | a read was abandoned between a frame's two-byte header and its payload, or a fragmented message was abandoned holding frames |
| `WebSocketByteTransport` | its client does |
| `MemTransport` | a cancelled multi-chunk read discarded bytes it had already taken |
| `HTTPResponse` | a cancelled `readexactly`/read-to-EOF discarded its accumulator |
| `BinaryChannel`, `LineChannel`, `CanonicalChannel` | their own framing stranded a fragment, **or** their carrier says it did |

Why it is a seam change and not a bug fix in one file: a carrier can be mid-frame before the
channel above it has been handed a single byte, so the channel's own answer is not merely
incomplete, it is confidently wrong. Measured over `astral.binary.v1`: a peer sends
`\x82\x0512345REALDATA` header-first, a 0.5 s deadline expires between the two halves,
`BinaryChannel.at_frame_boundary` answers `True`, `Session._recv` keeps the connection, and the
next transport read answers `b'12345'` — a message boundary the peer never sent, chosen by the
content of its data. That is section 3.7's forgery, one layer below where section 3.7 looks.

`WebSocketClient` additionally **latches a fault** when a read leaves it mid-frame, so a reader
with no channel above it — an accepted query's raw byte stream — is protected too. A read
abandoned *at* a boundary strands nothing and latches nothing, which is what keeps an idle follow
stream's deadline harmless over this carrier as much as over a socket.
