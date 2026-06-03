# astral-py

A Python client library for **astrald** — the node daemon of the
[Astral Network](https://github.com/cryptopunkscc/astral-docs). It speaks the
`apphost` IPC protocol so local apps and agents can route queries through the
node, serve inbound queries for identities they own, read/write the config
tree, resolve aliases, sign data, fetch objects, and more.

Pure standard library — **no third-party dependencies**. Implements all three
apphost transports the node exposes:

| Transport     | Endpoint (default)              | Streaming | Serving | Encoding |
|---------------|---------------------------------|:---------:|:-------:|----------|
| Binary (IPC)  | `unix:~/.apphost.sock`, `tcp:127.0.0.1:8625` | ✅ | ✅ | binary |
| WebSocket     | `ws://127.0.0.1:8624/.ws`       | ✅ | ✅ | JSON |
| HTTP          | `http://localhost:8624`         | response-only | ❌ | JSON |

The native binary channel is the canonical *Astral IPC*. The WebSocket
transport mirrors the reference `apphost-js` client and is the most robust path
for arbitrary structured results (JSON is self-describing). HTTP is the
simplest path for one-shot queries.

## Install

```bash
pip install -e .          # from this directory (src layout)
```

Requires Python 3.8+. The distribution name is `astral-ipc`; the import name is
`astral`.

> Note: the import name `astral` collides with the unrelated `astral`
> (astronomy) package on PyPI. If you have both installed, keep them in separate
> environments.

## Quick start

```python
import astral

# Connects to the local node. Default endpoint: unix socket if present, else TCP.
# A token (or $ASTRALD_TOKEN) authenticates the session; without one you are
# anonymous (allowed for outbound queries by default).
with astral.connect(token="...") as node:
    print(node.identity, node.alias, node.guest_id)

    # One-shot query, first result value:
    who = node.whoami()                      # apphost.whoami -> identity hex

    # Protocol helpers:
    ident = node.dir.resolve("alice")        # alias/hex -> identity
    keys  = node.tree.list("/mod")           # list child config keys
    sig   = node.crypto.sign_text("hello")   # "bip137:..."

    # Generic streaming query:
    with node.query("tree.list", {"path": "/mod"}) as stream:
        for obj in stream:                   # stops at eos
            print(obj.type, obj.value)
```

Pick a transport explicitly by passing an endpoint:

```python
astral.connect("ws://127.0.0.1:8624/.ws", token="...")   # WebSocket (JSON)
astral.connect("http://localhost:8624", token="...")     # HTTP
astral.connect("tcp:127.0.0.1:8625", token="...")        # binary over TCP
astral.connect("unix:/run/apphost.sock")                 # binary over unix socket
```

## Core concepts

A **query** is a call from a *caller* identity to a *target* identity with a
*query string* (`operation?param=value&...`). The target accepts it (opening a
**channel** / `Stream`) or rejects it with a numeric code. Over the channel both
sides exchange **objects**: an `AstralObject` is a `(type, value)` pair, where an
empty type is a raw binary blob. A stream of objects conventionally ends with an
`eos` object.

```python
from astral import obj, eos, ack, blob, AstralObject

obj("string8", "hello")     # a typed object
blob(b"\x00\x01")           # an untyped binary object
eos()                        # end-of-stream marker
```

### Queries and results

```python
# query() returns a Stream once the query is accepted.
stream = node.query("dir.resolve", {"name": "alice"})

# Convenience wrappers (open + collect + close):
objs  = node.call("tree.list", {"path": "/mod"})   # list[AstralObject], raises on error_message
value = node.call_one("apphost.whoami")            # first result's value
```

A query string can also be written inline; extra `args` are text-encoded and
appended:

```python
node.query("dir.resolve?name=alice")
node.query("objects.read", {"id": oid, "offset": 6, "limit": 5})
```

### Streams

```python
with node.query("crypto.sign_text", {"out": "json"}) as s:
    s.send(obj("string8", "sign me"))   # send input objects (binary/WS only)
    s.send_eos()
    signature = s.value()               # first result value

for obj in stream.results():            # raises RemoteError on error_message
    ...

raw = node.query("objects.read", {"id": oid}).read()   # unframed byte output
stream.cancel()                          # cancel an in-flight query, then close
```

`Stream` is a context manager; iterating it yields objects until `eos` or the
channel closes. `.collect()`, `.value()`, `.first()`, `.results()` and
`.read()` cover the common shapes.

### Serving inbound queries

Register a handler for an identity you own (requires an authenticated session).
The handler runs on a background thread per inbound query.

```python
def handle(q: astral.IncomingQuery):
    print(q.query, "from", q.caller)
    if q.op.startswith("admin"):
        q.reject(3)                      # non-zero reject code (1..255)
        return
    s = q.accept()                       # responder-side Stream
    s.send(astral.obj("string8", "hi"))
    s.send_eos()
    s.close()

reg = node.serve(handle)                 # for node.guest_id
# reg = node.register(identity, handle)  # for another owned identity
...
reg.unregister()                         # or use `with node.serve(handle) as reg:`
```

(Uses the apphost *register-service* mechanism: the host pushes inbound queries
on the registration connection, and each `accept()` opens a fresh attach
connection. The *register-handler* dial-back mechanism — `apphost.bind` — is
available via `transport.bind(token)` for advanced use.)

### Protocol helpers

Exposed as attributes of the client:

```python
node.apphost.whoami()                       # -> identity
node.apphost.create_token(identity)         # -> AccessToken(identity, token, expires_at)
node.apphost.register()                     # bootstrap a fresh guest identity + token

node.dir.resolve(name)                      # alias/hex -> identity
node.dir.get_alias(identity)                # -> alias or None
node.dir.set_alias(identity, "alice")       # set/remove an alias

node.tree.get("/mod/tcp/settings/listen")   # -> stored value
node.tree.list("/mod")                       # -> list[str]
node.tree.set(path, astral.obj("bool", True))
node.tree.delete(path)

node.crypto.sign_text("hello")              # -> "<scheme>:<sig>"
node.crypto.public_key()                     # -> "<scheme>:<hex>"

node.objects.read(object_id)                # -> bytes (raw)
node.objects.describe(object_id)            # -> list of descriptor values
node.objects.contains(object_id)            # -> bool
```

Helpers that return scalar common types (identity, string, bool, …) work over
every transport. Helpers that return **structured** objects (e.g.
`apphost.access_token`, `mod.objects.describe_result`) decode cleanly over the
JSON transports (`ws://`, `http://`); over the binary transport such payloads
are handed back as raw bytes.

### Object IDs

```python
oid = astral.compute_object_id(b"hello world")   # ObjectID(size, hash)
str(oid)                                          # "data1..." (zBase32)
astral.ObjectID.parse("data1...")                 # round-trips
astral.compute_object_id(b"\x15", "uint8")        # typed: includes Stamp + header
```

## Command line

A small `astral-query`-style CLI ships with the package:

```bash
python -m astral dir.resolve -name alice
python -m astral tree.list -path /mod --json
python -m astral --endpoint ws://127.0.0.1:8624/.ws apphost.whoami
python -m astral objects.read -id data1...        # writes raw bytes to stdout
python -m astral alice:some.op -param value       # target:operation form
```

After `pip install`, the `astral-query` console script is also available.

Configuration via environment:

* `ASTRALD_TOKEN` / `ASTRAL_AUTH_TOKEN` / `ASTRAL_TOKEN` — auth token.
* `ASTRALD_ENDPOINT` / `ASTRAL_ENDPOINT` — default endpoint.

## Wire format

The library implements the encodings described in astral-docs:

* **Binary** (big-endian): length-prefixed `string8..string64` / `bytes8..bytes64`,
  `uint8..uint64` / `int8..int64`, `bool`, `identity` (a `bool` presence flag
  then the 33-byte compressed secp256k1 key when present), `nonce64` (8 bytes),
  `time` (uint64 ns), arrays (uint32 count). A channel frame is
  `string8(type) ++ bytes32(payload)`.
* **JSON**: the `{ "Type": ..., "Object": ... }` envelope.
* **Text**: `#[type]` + separator + payload; query-string params use the
  payload-only form.
* **Object IDs**: `uint64 size ++ sha256(binary-encoding)`, zBase32-encoded with
  leading `y`s stripped and a `data1` prefix.

### Assumptions

The docs fully specify the JSON path. For the binary path:

* `identity` is a `bool` presence flag (`0x01` present / `0x00` null) followed by
  the 33-byte compressed key when present — verified against a live node's
  `host_info_msg`.
* `zone` is assumed to be a single-byte bitmask (`device=1`, `virtual=2`,
  `network=4`; `"dvn"` = all). This is the one field not yet confirmed against a
  node; it only affects routing scope.

If you hit a binary-encoding mismatch against a specific node build, use the
`ws://` transport (JSON), which is unaffected by these assumptions.

## Limitations

* Synchronous (blocking) API; serving uses background threads. No asyncio layer
  (yet).
* HTTP transport is request/response only — no input streaming, no serving.
* The JSON WebSocket transport is text-only, so it cannot carry unframed raw
  byte output (`objects.read`); use the binary or HTTP transport for that.

## Development

```bash
# run the test suite (stdlib unittest; no pytest required)
PYTHONPATH=src python -m unittest discover -s tests -v
```

Tests run entirely against in-process mock nodes (a binary apphost server and a
WebSocket server), so no live astrald is needed. They also check the codecs
against the byte examples in the docs.

## Layout

```
src/astral/
  __init__.py        public API
  client.py          connect(), Client
  stream.py          Stream
  objects.py         AstralObject + constructors
  codec.py           binary read/write primitives + channel framing
  payload.py         common-type payload (en/de)coding for the binary channel
  objectid.py        ObjectID + zBase32
  encoding.py        text encoding, query strings, JSON envelopes, zones
  messages.py        mod.apphost.* control messages (binary + JSON)
  errors.py          exception hierarchy
  cli.py             `python -m astral` command line
  transport/
    base.py          Channel / Transport ABCs, endpoint parsing
    session.py       shared apphost session (handshake/query/register/attach)
    binary.py        native binary channel (unix/tcp)
    websocket.py     minimal RFC 6455 client + JSON channel
    http.py          HTTP request/response transport
  protocols/         dir, tree, crypto, objects, apphost helpers
examples/            runnable examples
tests/               unittest suite with mock nodes
```

## License

MIT — see [LICENSE](LICENSE).
