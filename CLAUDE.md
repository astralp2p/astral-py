# CLAUDE.md

`astral-py` is an asyncio client for the astrald **apphost IPC** protocol.
Distribution `astral-ipc`, import package `astral`, standard library only,
Python >= 3.11. The tree is a from-scratch rewrite; commit `e580b03` deleted the
synchronous SDK, and no file in it is a reference for anything.

Architecture reference: `docs/architecture.md`. It is the binding specification;
section numbers below cite it. Section 11 holds
amendments that supersede the sections they name. **Section 11.4 is deferred**:
the wire core's `Any`/nil behaviour stays as it is.

Authorities, in precedence order: the live node, astral-go
(`../astral-go/main` @ `5c18d9c`, the commit the node pins), astrald, astral-docs.
Where the docs disagree with the node, the node wins and the disagreement is a
bug report in design section 9.2. A wire fact sourced from astral-docs alone is
not established.

## Three layers, one arrow

| Layer | Modules | Rule |
|---|---|---|
| Wire core | `errors`, `wire`, `types`, `spec`, `record`, `registry`, `object`, `primitives`, `objectid`, `querystring`, `blueprint`, `bip39`, `codec/{binary,jsoncodec,text}` | synchronous, I/O-free |
| Transport and session | `transport/{base,socket,mem,websocket,http}`, `channel/{binary,jsonl,lines,textchan,canonical}`, `session`, `conn`, `context` | async |
| Client and modules | `client`, `stream`, `serve`, `registrar`, `api/*` | async |

The arrow points one way: module clients → session → channel → transport, and
every one of them → wire core. The wire core imports nothing from the other two,
and **no `asyncio` import may reach it**.

The wire core is synchronous because every framing the SDK speaks is length- or
line-delimited, so a complete payload is in memory before decoding starts. An
`await` in a scalar decoder buys nothing and costs a coroutine per field.
Corollary, and a hard rule: a type that reads to EOF (`Blob`, `UnparsedObject`)
receives a `Reader` bounded to exactly one frame's payload and never sees the
socket.

## The schema drives all four encodings

A wire type is a dataclass under `@record("mod.x.y")` whose fields carry their
`Spec` in `field(metadata=…)` via `record.wire(name, spec)`. The Spec tree is the
single source of truth, and `codec/binary.py`, `codec/jsoncodec.py`,
`codec/text.py` and `objectid.py` all walk that one declaration. Schema
derivation from type hints does not exist and is not to be added: `str` cannot
distinguish `string8` from `string32`, `bytes` cannot distinguish `bytes8` from
`identity` (design 2.5).

Consequence: one declaration yields the binary, JSON, text and canonical forms
and the ObjectID. A hand-written `write_payload` on a record is a defect; the
escape hatch for a shape the Spec tree cannot express is design 2.5's, and
`mod.nodes.node_info` is the one type in the tree that takes it.

`@record` registers into `registry.default_blueprints()`, and registration is a
side effect of import. `astral/api/__init__.py` therefore imports every module
eagerly and `astral/__init__.py` imports `astral.api` on its last line.
**Whether an object decodes must never depend on which module a caller imported
or which `client.<module>` property it touched.** Construction of a module client
is lazy; registration is not.

## The wire facts that were expensive to establish

Four containers carry a type tag, and it sits in a different place in each.
Conflating the first two is the most common reimplementation error: they invert.

| Container | Layout |
|---|---|
| Binary channel frame | `string8(type) ++ bytes32(payload)` — type **outside** the length |
| Bundle element | `bytes32( string8(type) ++ payload )` — type **inside** the length |
| Canonical | `Stamp ++ string8(type) ++ payload` — no length at all |
| Polymorphic (`Any`) field | `string8(type) ++ payload` — no length |

**`identity` is 33 flat bytes.** No presence flag, no length prefix. A `0x01`
seen in front of an identity belongs to the enclosing slot — a `Ptr(identity)`
field, or a container element or map value. Verified live: `apphost.whoami`
answers a frame whose `bytes32` length is exactly 33, and the `mod.dir.alias_map`
payload is `00000001 000a "furry-bolt" 01 <33B>` where the `01` is the map
value's. Pinned by `tests/test_risk_register.py::R1IdentityWidth`. The width is
load-bearing for every op that answers an identity — `dir.resolve`,
`apphost.whoami`, `objects.find`, `user.list_siblings` among them: one extra byte
desynchronises the payload and every field after it decodes as something else.

**The presence byte belongs to the container, and is encoded from the spec and
never from the value** (design 2.3). `Ptr` emits its own nil flag; `Any` emits
its own type tag and a zero-length tag is nil; everything else in a slice
element, an array element or a **map value** slot is preceded by a synthesized
`0x01`. **Map keys never carry one.** Write `0x01`; on read accept `0x01` and
also accept `0x00` as absent, because a blueprint-built peer legally emits it.

**A bare Go `string` struct field is `string32`**, and a bare `[]byte` field is a
slice of `uint8`, not `bytesN`. The docs never state a width. This is the
highest-impact silent-corruption trap in the corpus (design 9.2, D-9);
`routing.op_spec` is the pinned instance,
`tests/test_risk_register.py::R14OpSpecStringWidth`.

**Map order is the wire format.** Encode each key and each value into separate
buffers, sort the pairs by `bytes` comparison of the encoded key, then emit.
Python dict insertion order never reaches the wire; content hashes depend on it.

**`eos` is a per-op convention emitted by the op handler, not a transport
signal.** `apphost.whoami` and `dir.alias_map` end at a bare EOF with no `eos`;
`dir.filters` ends at an `eos`. Terminate on `eos` **or** EOF, never block
waiting for `eos`, and read `Stream.terminated_by` to learn which happened.

**`mod.nodes.node_info` carries a flat identity too**, and for a different
reason: astral-go hand-rolls its `WriteTo` instead of using the reflective codec,
so the `*astral.Identity` field gets no presence byte. Decode it the way the node
sends it (`api/nodes.py`).

Global rules: big-endian everywhere, two's complement, IEEE 754, no varints, no
padding, no field names on the binary wire — order is the schema. Codecs do not
return byte counts; derive from `Reader.pos`, because astral-go's `n` is wrong
for eight types.

## Op modes

Six modes. **Op shape is a per-op contract that nothing on the wire reveals**, so
every module-client method declares its own and no code infers one.

| Mode | Shape | Helper |
|---|---|---|
| RR | args in the query string, exactly one object | `Client.call_one` |
| ST | zero or more objects, `eos` or EOF | `Client.call`, `Client.stream` |
| ST+follow | the first `eos` is a snapshot/live separator | `Client.follow` → `Stream.follow/snapshot/live` |
| WA | the client sends objects on the channel body | `Client.call_with` |
| BD | the caller drives both directions | `Client.query` → raw `Stream` |
| RAW | the response body is unframed bytes | `Client.call_raw` |

The mode declaration exists to prevent two failures that used to be silent:

1. **Body input passed as a query argument.** A query argument on
   `crypto.verify_*` never verifies and never says so. The confirmed body-input
   op set is design 4.7's.
2. **The wrong reader on a follow stream.** `async for` over a follow stream
   drops every live object; `snapshot()` on an op with no separator — `tree.get`
   — blocks to the deadline holding one of the node's 32 workers. `Stream`
   refuses the reader its op does not have.

`objects.read` is the only RAW op. A session that cannot carry raw bytes
(`astral.json.v1` WebSocket, HTTP) raises `TransportUnsupported` rather than
answering with something approximate.

## Connection hygiene is a correctness property

astrald's apphost module runs `Workers: 32` pulling from an unbuffered channel,
shared by every app on the machine, and never notices a peer that vanished. A
leaked `Client`, `Stream` or service therefore burns one worker until the node
restarts, and thirty-two leaks wedge the node for every app on the box. This was
observed, not predicted: the node was found in exactly that state, 32 sockets in
`CLOSE-WAIT`, during design (design 3.9).

- `Client` and `Stream` are async context managers. `async with` is the contract
  and there is no `__del__` fallback.
- `DEFAULT_MAX_CONCURRENCY = 8` and `DEFAULT_MAX_PERSISTENT = 4` are a
  shared-resource budget, not a performance knob.
- `connect()` closes its greeting connection before returning.
- `CONNECT_TIMEOUT` covers reading `host_info_msg`, not merely the TCP connect,
  so a saturated node surfaces as `NodeUnavailable` in seconds rather than
  hanging forever.
- Every test closes what it opens; `mock_apphost.leaked_sockets` asserts it.

Two structural rules follow from the channel→raw handover at
`query_accepted_msg`, and both are load-bearing (design 3.2):

1. **A channel that can be handed over holds no read buffer of its own.** Every
   framing read goes through the same `asyncio.StreamReader` the raw stream will
   use, so `detach()` is a no-op handover of the identical object. Do not port
   astral-go's `streams.ContextReader`. `detach()` is legal on `BinaryChannel`
   alone; a line-oriented channel keeps surplus bytes and refuses it.
2. **One `write()` per object.** A frame is serialised whole and issued in one
   call, so frames cannot interleave and cancellation cannot land mid-frame.
   **No write lock exists anywhere in the SDK.** Do not add one.

## Tests

```bash
cd /home/intern0/work/astralp2p/astral-py/dev--asyncio-rewrite
PYTHONPATH=src python3 -m unittest discover -s tests
```

stdlib `unittest`, `IsolatedAsyncioTestCase` for async. No pytest, no
third-party test dependency. Verified this run: the whole suite passes with no
node and no network. **That is the invariant — the suite must stay green with no
node reachable, and every async test must be bounded.**

The invariant is about the machine, not only the socket, and stating it as "no
node reachable" is what let it be read as satisfied when it was not. A node is
reachable on the machine this suite is developed on, and design section 3.3 makes
`connect()` fall back to `ASTRAL_ENDPOINT` / `ASTRALD_ENDPOINT` and to
`ASTRALD_APPHOST_TOKEN` / `ASTRALD_TOKEN` / `ASTRAL_AUTH_TOKEN` / `ASTRAL_TOKEN`
when it is handed neither — so an exported token is offered to a mock host that
has none and the test dies on `AuthFailed` with no node involved at all. So the
invariant in full: **green whatever the ambient environment holds, node running
or not.** `mock_apphost.blank_ambient_environment()` runs at import and blanks
those six; `test_mock_apphost.AmbientEnvironmentTest` pins both that it ran and
that every test module calling `connect` imports it, because an import-time guard
is worth exactly its reach. Tier C is unaffected: its opt-ins are
`ASTRAL_TEST_ENDPOINT` and `ASTRAL_TEST_TOKEN`, deliberately different names.

- **Tier A — byte vectors, no node.** `tests/vectors/wire_vectors.json` is pure
  data and **must never import the SDK**: a corpus generated by the thing it
  validates checks nothing. Every vector names its authority and its `ref`.
  Never edit that file to make a test pass.
- **Tier B — in-process mocks, no node.** `mock_apphost.py` is the host the
  client dials, served over both `MemTransport` and a real loopback listener;
  `mock_dialer.py` is the host that dials **us** for register-handler;
  `mock_web.py` is HTTP/1.1 and RFC 6455. Framing in all three is hand-rolled on
  purpose, so a wrong layout in the SDK cannot agree with a wrong layout in the
  harness.
- **Tier C — live node.** Every case subclasses `live_support.LiveCase`, which
  builds one client per test at `max_concurrency=4` and counts descriptors. The
  tier skips whole, once, with a reason, unless `ASTRAL_TEST_ENDPOINT` names a
  node that greets one shared precheck bounded at `CONNECT_TIMEOUT * 3`.

```bash
ASTRAL_TEST_ENDPOINT=unix:/home/intern0/.apphost.sock \
    PYTHONPATH=src python3 -m unittest discover -s tests
```

A citation to a sibling repository is read through `tests/reference.py`, which
runs `git show <rev>:<path>`, so an upstream pull cannot turn this suite red.

### Live-node discipline

- **Never route `objects.new?type=mod.nodes.node_info`.** It panics astrald
  deterministically on every build carrying astral-go `5c18d9c`: the registry's
  zero value holds a nil `*astral.Identity`, `NodeInfo.WriteTo` hands it to
  `streams.WriteAllTo`, and `Identity.WriteTo` has a value receiver, so the
  dereference happens on a goroutine with no recover. A fix exists on an unmerged
  branch, so the running node still dies. Decoding a `node_info` is safe.
  `FORBIDDEN_LIVE_QUERIES` in `tests/test_risk_register.py` names the query and a
  test asserts no file in `tests/` sends it.
- Never leave a follow stream undrained, `log.listen` above all.
- Reuse one session for many ops and close it explicitly. Read-only ops only; the
  excluded mutating set is design 7.3's.
- Never restart or reconfigure the node. If it stops answering, stop and report.

## Adding a module client

Read `api/dir.py` and `api/objects.py` before writing one; they are the pattern.
The op inventory is `survey-go-api.md`, derived from the live `shell.spec`
registry. Implement what it lists and invent nothing.

1. One file, `api/<module>.py`: wire types as `@record` dataclasses, op-name
   constants (`OP_ALIAS_MAP: Final = "dir.alias_map"`), a `<MODULE>_TYPES`
   sequence, then a `ModuleClient` subclass whose `TYPES` names them.
2. Every op is argument marshalling plus **one** call to `call`, `call_one`,
   `call_raw`, `call_with`, `stream` or `follow`. No op has a hand-written
   transport path. The docstring states the mode and the termination; the answer
   goes through `self._expect`, which raises `ProtocolError` because a wrong type
   is the remote breaking its own contract.
3. Method name is the op name with `.` for `_`; the batch form is `<op>_many`;
   the follow form is `<op>_follow` — never a bare `follow`, which collides with
   the `Stream.follow()` reader.
4. Every method takes `**kw` and passes the query keywords through unread, so a
   misspelled one fails in `query()` instead of being dropped.
5. Arguments are the server's field names snake-cased and **lowercase**: matching
   is case-sensitive and unknown keys are silently dropped. Values go through
   `self._param` / `self._encode`, which is the bare payload half of the text
   encoding with no `#[type]` header. Query strings are built with sorted keys.
6. Type names are module-prefixed (`mod.dir.alias_map`); op names are not
   (`dir.alias_map`). `mod.` is never part of an op name. The literal exceptions
   to the prefix rule are design 5.1 rule 6's.
7. Add the module to `api/__init__.py` **and** a `functools.cached_property` to
   `Client`. Both are enforced by tests walking the directory
   (`tests/test_api_apphost.py`, `tests/test_client.py::ModuleClientAttachmentTest`),
   because the unenforced version of this rule let five modules land with no
   property while the suite stayed green. A module that declares no op —
   `endpoints`, `exonet` — has neither client nor property; excluding a module
   means excluding its ops, not its types.
8. Never port an astral-go client bug. The known set is design 5.1 rule 7's.

## Prose in this repository

Comments and docs follow `~/.claude/STYLE.md`. Every claim about the wire, a
reference repository or the node carries its support: **verified** (cite the live
exchange or the test that pins it), **sourced** (cite `path:line` at a pinned
revision) or **inferred** (state the basis). A comment that states something
untrue is a defect and is fixed on sight. A claim of enforcement that is not
enforced is worse than no claim, because it stops the next reader looking.

## Never

- Import `asyncio` in the wire core.
- Apply design section 11.4, or change the wire core's `Any`/nil behaviour.
- Edit `tests/vectors/wire_vectors.json`.
- Widen `astral/__init__.py`. The facade is `connect`, `Client`, `Identity`,
  `ObjectID`, `Zone` and the exception hierarchy; everything else is named where
  it lives, so an internal rename is not a breaking change.
- Uncomment `[project.scripts]` in `pyproject.toml` before `src/astral/cli.py`
  exists; it puts an `astral-query` on the user's PATH that fails with
  `ModuleNotFoundError`.
