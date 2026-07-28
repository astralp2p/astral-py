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
| Wire core (synchronous, I/O-free) | `wire`, `types`, `spec`, `record`, `registry`, `object`, `primitives`, `blueprint`, `objectid`, `querystring`, `bip39`, `codec/{binary,jsoncodec,text}` | complete |
| Transport and session (async) | `transport/{base,socket,mem,websocket,http}`, `channel/{binary,jsonl,lines,textchan,canonical}`, `session`, `conn`, `context` | complete |
| Client, serving and module clients | `client`, `stream`, `serve`, `registrar`, `api/*` | fourteen modules |

The module clients are Tier 1 -- `apphost`, `dir`, `tree`, `crypto`, `auth`,
`objects`, `services` -- Tier 2 -- `user`, `bip137sig`, `ip`, `exonet` -- and the
experimental Tier 3 pair `nodes` and `nat`, whose ops refuse to run without
`experimental=True` while their wire types decode always. `endpoints` and
`exonet` ship types and no ops, because `mod.nodes.node_info` cannot decode
without `mod.tcp.endpoint`. `shell` carries the one introspection op,
`shell.spec`, which answers the node's whole op registry anonymously and is how
this SDK checks itself against the node it is talking to.

The `astral-query` command has landed, in `cli.py`, and `[project.scripts]`
declares it. It is also `python -m astral`, which needs only the package on
`sys.path`.

All four channel formats are reachable from every entry point. `client.call(
"apphost.whoami?out=json")`, `fmt_out="text"`, `astral-query --out canonical` and
a responder's `accept(fmt_out=...)` each open the channel the token names, and
the four decode one op's answer to the same objects against a live node. One
hazard is the caller's and cannot be checked here: **`in=` reaches only seven of
the nineteen ops these modules cover**, and the other twelve read the body as
`bin` whatever was asked, so objects written in another framing reach a binary
reader. `out=` is honoured by every op.

The WebSocket and HTTP transports have landed. A `ws://` or `wss://` endpoint is
dialable wherever a `tcp:` one is -- it carries the same session over the
`astral.binary.v1` subprotocol -- and `astral.connect("ws://127.0.0.1:8624/.ws")`
is a whole client. An `http://` endpoint is not dialable at all: an HTTP request
carries its query in the request line, so one request is one query and
`astral.transport.http.query()` is its entry point.

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

### The six op shapes

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
stream = await client.query("some.long_lived_op")       # BD: both directions

async with client.follow("objects.scan?repo=main&follow=true") as s:  # ST+follow
    async for value in s.snapshot():                    # the stored state
        ...
    async for update in s.live():                       # everything after
        ...
```

ST+follow means the op sends an `eos` that is a **snapshot/live separator**
rather than a terminator, and that is a per-op fact the wire does not carry.
`objects.scan?follow=true` and `services.discover?follow=true` send one;
`tree.get?follow=true` does not — its single `eos` is the end, so it is read
with `async for` and `client.stream()`, which is what `Tree.get_follow` returns.
Both mismatches used to fail in silence, so the stream now refuses the reader
its op does not have: `async for` on a follow stream would drop every live
object, and `snapshot()` on `tree.get` would block until the deadline holding
one of the node's 32 workers.

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

Attached to `Client` as cached properties, one per node module -- `apphost`,
`auth`, `bip137sig`, `crypto`, `dir`, `ip`, `nat`, `nodes`, `objects`,
`services`, `shell`, `tree`, `user`:

```python
await client.apphost.whoami()
await client.apphost.list_tokens()                  # every token, in plaintext
await client.dir.resolve("alice")                   # alias/hex -> Identity
await client.dir.apply_filters("localnode", identity="alice")
await client.objects.describe(oid)                  # -> list[Descriptor]
await client.tree.get("/some/path")
await client.nodes.links(experimental=True)         # Tier 3: opt in per call
await client.shell.spec()                           # every op the node has
```

Importing `astral` registers every wire type in the package, so whether an
object decodes never depends on which property was touched first. `nodes` and
`nat` are experimental and their **ops** are gated; their **types** decode
always, because a `mod.nodes.link_info` can arrive on any stream.

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

## `astral-query`

One query, from a shell. Installed as the console script `astral-query`, and
reachable from a checkout as `python -m astral`.

```
astral-query [global options] [target:]<operation> [-param value ...] [-- raw args]
```

```bash
astral-query apphost.whoami                       # identity  03b27049…
astral-query dir.resolve -name furry-bolt         # one line per object
astral-query --json dir.alias_map                 # {"Type": …, "Object": …}
astral-query alice:objects.search -q holiday      # target resolved via dir.resolve
astral-query --follow objects.scan -repo main     # snapshot, then live updates
astral-query --input signme.txt crypto.sign_text  # objects on the channel body
astral-query objects.read -id data1… > file       # raw bytes, no framing
```

The operand is a query string and not a name from a table, so an op no module
client wraps is reached the same way as one that is. Default output is one
`type<TAB>value` line per object; `--json` is one envelope per line;
`objects.read` writes its body to stdout unaltered. An `error_message` goes to
stderr and iteration continues, so a partial stream still prints.

Global options: `--endpoint`, `--token`, `--target`, `--caller`, `--zone dvn`,
`--filters a,b`, `--in`/`--out` (validated client-side), `--timeout`,
`--follow`, `--input FILE|-`, `-p name=#[type]value`, `--json`, `--dump-wire`,
`--version`.

Exit codes: **0** ok, **1** connect failure, `AstralError`, or any
`error_message` seen, **2** usage, **3** `QueryRejected` with the responder's
code on stderr, **130** interrupted, **141** closed pipe.

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

stdlib `unittest`, no third-party test dependency either. Three tiers. Tier A
round-trips the byte-vector corpus in `tests/vectors/`, Tier B drives in-process
mock servers over both a memory transport and a real loopback listener, and both
need no node and no network and gate every commit. Tier C runs only when
`ASTRAL_TEST_ENDPOINT` names a reachable astrald, and skips cleanly with a
reason otherwise:

```bash
ASTRAL_TEST_ENDPOINT=unix:~/.apphost.sock \
    PYTHONPATH=src python3 -m unittest discover -s tests
```

Tier C is read-only, bounded and closes every stream, because a leaked stream
holds one of the node's 32 apphost workers until the node restarts.

### What is not verified yet

Three things an embedder should know before treating this as finished:

* **The inbound serving path is mock-verified only.** `serve.py` and
  `registrar.py` -- the listener, the accept loop, the token check, the answer
  deadline and the reconnect cycle -- are exercised against `MockDialer` and
  `MockApphost` and have never run against a node, because the live half needs
  an apphost token (`ASTRAL_TEST_TOKEN`) and none was available. Design risk
  R-16, whether astrald's IPC worker closes a donated attach-query socket, is
  open for the same reason.
* **`RuntimeRecord`'s polymorphic-nil handling is a known open defect.** Design
  amendment 11.4 records two proved faults in it and defers both. Nothing in the
  module clients reaches them; `Client.query(allow_unparsed=True)` and
  `Objects.learn` do, so an application that decodes an unregistered type should
  not rely on a byte-exact round trip until 11.4 is settled.
* **`py.typed` ships and no type checker runs in this tree.** The annotations
  are there and are not machine-verified, and there is no CI: the three-tier
  suite, the wheel build and the console-script import are run by hand.

## License

MIT — see [LICENSE](LICENSE).
