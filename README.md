# astral-py

An **asyncio** client library for **astrald** — the node daemon of the
[Astral Network](https://github.com/astralp2p/astral-docs). It speaks the
`apphost` IPC protocol, so a local app or agent can route queries through the
node, read the directory, and exchange typed objects over the binary wire.

Pure standard library — **no third-party dependencies**. Distribution name
`astral-ipc`; import name `astral`.

> The import name `astral` collides with the unrelated `astral` (astronomy)
> package on PyPI. If you have both, keep them in separate environments.

## Install

```bash
pip install -e .          # from this directory (src layout)
```

Requires **Python 3.11 or newer**. `asyncio.TaskGroup` and `asyncio.timeout()`
are structural to the design, not conveniences.

## What ships today

This tree is a from-scratch rewrite, landing in layers. What exists now:

| Layer | Modules | State |
|---|---|---|
| Wire core (synchronous, I/O-free) | `wire`, `types`, `spec`, `record`, `registry`, `object`, `primitives`, `blueprint`, `objectid`, `querystring`, `codec/{binary,jsoncodec,text}` | complete |
| Transport and session (async) | `transport/{base,socket,mem}`, `channel/{__init__,binary}`, `session`, `conn`, `context` | complete for binary IPC |
| Client and module clients | `client`, `stream`, `api/{apphost,dir}` | `apphost` and `dir` |

Not yet landed, in implementation order: inbound serving (`serve.py`,
`registrar.py`), the remaining Tier 1 modules (`crypto`, `auth`, `services`,
`tree`, `objects`), the `astral-query` CLI, Tier 2 (`user`, `bip137sig`, `ip`,
`exonet`), the JSON/text/canonical channels with the WebSocket and HTTP
transports, and the gated Tier 3 modules. Asking for a channel format other than
`bin`, or for a `ws://`/`http://` endpoint, raises `TransportUnsupported` naming
the step it lands in rather than doing something approximate.

## Quick start

```python
import asyncio

import astral


async def main() -> None:
    # Default endpoint: the unix socket if it exists, else tcp:127.0.0.1:8625.
    # Without a token the session is anonymous, which the node allows for
    # outbound queries by default.
    async with await astral.connect() as client:
        print(client.host_id, client.host_alias, client.guest_id)

        who = await client.apphost.whoami()          # -> Identity
        aliases = await client.dir.alias_map()       # -> AliasMap
        print(aliases.alias_of(who))

        async with client.stream("dir.filters") as s:
            async for obj in s:                      # stops at eos or EOF
                print(obj)


asyncio.run(main())
```

**Close what you open.** astrald serves apphost from a fixed pool of 32 workers
shared by every app on the machine and never notices a peer that vanished, so a
`Client` or a `Stream` left open burns one worker until the node restarts.
`async with` on both is the contract; there is no `__del__` fallback, and a
`Client` bounds how many connections it may hold at once for the same reason.

## Core concepts

A **query** goes from a *caller* identity to a *target* identity carrying a
*query string* (`operation?param=value&…`). The target accepts it — after which
the connection **is** that query's bidirectional stream — or rejects it with a
numeric code. Over the stream both sides exchange **objects**: typed values whose
type name is a registry key. A stream ends at an `eos` object **or** at a bare
EOF, and which one is a per-op contract that the wire does not carry.

### The five op shapes

Op mode is declared by the caller and never inferred, because nothing on the
wire reveals it: `apphost.whoami` answers one object and closes with no `eos`,
`dir.filters` answers several and ends with one, and `objects.read` answers no
objects at all.

```python
one   = await client.call_one("dir.alias_map")          # RR: exactly one object
many  = await client.call("dir.filters")                # ST: to eos or EOF
data  = await client.call_raw("objects.read?id=data1…") # RAW: unframed bytes
outs  = await client.call_with("crypto.sign_text",      # WA: input on the body
                               text_object, expect=1)

async with client.follow("tree.get?path=/mod&follow=true") as s:  # ST+follow
    async for value in s.snapshot():                    # the stored state
        ...
    async for update in s.live():                       # everything after
        ...
```

`timeout` on `call`, `call_one`, `call_raw` and `call_with` bounds the **whole**
call — route and answer together — because those own the stream. `query()` hands
the stream back, so its `timeout` covers the route only and the deadline on the
body belongs to the caller.

### Streams

```python
async with client.stream("apphost.list_tokens") as s:
    objects = await s.collect(timeout=5.0)
    print(s.terminated_by)          # "eos" or "eof"

async with client.stream("crypto.sign_text") as s:
    await s.send(text_object)       # body input; never a query argument
    signature = await s.value()
```

`async for` raises `RemoteError` on an `error_message` object rather than
yielding it, because a pipeline stage that yields one feeds a wrong-typed object
to the next. `raw_objects()` is the view that yields everything and raises
nothing.

### Module clients

Attached to `Client` as cached properties, one per node module:

```python
await client.apphost.whoami()
await client.apphost.list_tokens()                  # every token, in plaintext
await client.dir.resolve("alice")                   # alias/hex -> Identity
await client.dir.get_alias(identity)
await client.dir.apply_filters("localnode", identity="alice")
```

Importing `astral` registers every wire type in the package, so whether an
object decodes never depends on which property was touched first.

### Object IDs

```python
from astral.objectid import object_id, object_id_of_bytes

oid = object_id_of_bytes(b"hello world")       # ObjectID(size, hash)
str(oid)                                       # "data1…" (zBase32)
astral.ObjectID.parse(str(oid))                # round-trips
object_id(some_typed_object)                   # typed: Stamp + type + payload
```

### Errors

Everything the SDK raises on its own behalf is an `astral.AstralError`. Argument
and state faults carry their stdlib base as well, so both reflexes work:

```python
try:
    await client.call_one("dir.resolve?name=nope")
except astral.RemoteError as exc:
    print(exc.query, exc.message)        # the op, and the responder's own text
except astral.AstralError:
    ...
```

`BadArgument` is also a `ValueError`, `BadArgumentType` also a `TypeError`, and
`StreamClosed`, `ConcurrentRead` and `ClientClosed` are also `RuntimeError`.

## Wire format

Implemented per astral-docs, with the divergences the design records:

* **Binary**, big-endian throughout: `string8..string64` / `bytes8..bytes64`,
  `uint8..uint64` / `int8..int64`, `bool`, **`identity` as 33 flat bytes with no
  presence flag** (the flag belongs to an enclosing `*Identity` pointer field),
  `nonce64`, `time` (uint64 ns), `duration` (signed int64 ns), `zone`,
  `object_id.sha256`, plus the seven composite kinds — including the **map**
  kind, sorted by encoded key bytes. A channel frame is
  `string8(type) ++ bytes32(payload)`; a bundle element inverts that order.
* **JSON**: the `{"Type": …, "Object": …}` envelope.
* **Text**: `#[type]` + separator + payload; query-string parameters carry the
  payload-only half.
* **Object IDs**: `uint64 size ++ sha256(canonical form)`, zBase32 with leading
  `y`s stripped and a `data1` prefix.

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Three tiers. A and B need no node and no network and gate every commit; C runs
only when `ASTRAL_TEST_ENDPOINT` names a reachable astrald, and skips cleanly
with a reason otherwise.

## License

MIT — see [LICENSE](LICENSE).
