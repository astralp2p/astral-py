# CLAUDE.md

Python client for the astrald **apphost IPC** protocol. The protocol spec lives
in the sibling `../astral-docs/` repo — read `topics/astral-ipc.md`,
`topics/*-transport.md`, `core-primitives/channel.md`, and `common-types/`
before changing wire code.

## Architecture

Layered, transport-agnostic core with three interchangeable transports:

- `codec.py` / `payload.py` / `objectid.py` / `encoding.py` / `messages.py` /
  `record.py` / `registry.py` — pure wire format (binary, JSON, text). No I/O.
- `transport/base.py` — `Channel` (frames objects) and `Transport` ABCs.
- `transport/session.py` — `ChannelTransport` implements the apphost session
  (handshake → query/register/attach) **once**; binary and WebSocket only
  differ in their `Channel` (`_open_channel`). HTTP is a separate `Transport`.
- `client.py` — `Client` facade + `connect()`; `stream.py` — `Stream`.

Key invariant: `Channel.recv()` returns a `messages.Message` for known
`mod.apphost.*` control types and an `AstralObject` for everything else. Both
the binary and WebSocket channels honour this via `messages.REGISTRY`.

Structured records: `record.py`'s `Record` base carries a `(python_attr,
wire_name, kind)` `FIELDS` schema and decodes over **both** framings — binary via
`read_from`/`write_to` (dispatched from `payload.decode_payload` through the
name-keyed `registry.py`) and JSON via `from_value(dict)`. `@register(type)` adds
a record so binary decode yields a typed value instead of raw bytes (mirrors
astral-go's Blueprints). This is how structured objects decode over binary IPC,
not only over JSON. Sending is symmetric: a registered `Record` value wrapped in
an `AstralObject` is encoded via `write_to` (binary, `payload.encode_payload`) or
`encode_json` (`encoding.to_json_envelope`), so typed records can be sent, not
just received. Beyond scalars, `FIELDS` kinds compose: `("array", …)`,
`("record", …)`, `("bytes", n)`, `("ptr", …)`, and an opaque `("bundle",)`.

## Two distinct framings (do not conflate)

- **Channel frame** (transport): `string8(type) ++ bytes32(payload)`.
- **Generic `object` type** (a field inside structs): `string8(type) ++ payload`
  with NO length prefix (self-delimiting). The `payload` is the type's own
  binary encoding (e.g. `string8 "hi"` → `\x02hi`, `uint8 21` → `\x15`).

`object_binary_encoding()` (for Object IDs) additionally prepends the
`Stamp (0x41444330) + string8(type)` header for typed objects only.

## Transports & when each works

- **binary** (`unix:`/`tcp:`) — canonical, full features. Structured results
  decode to typed `Record`s when their type is registered (`registry.py`);
  unregistered/unknown structured types still come back as raw bytes.
- **websocket** (`ws://`) — full features, JSON envelopes (self-describing).
  Auto-injects `in=json&out=json`. Text-only: no raw-byte output ops.
- **http** (`http://`) — request/response only; no input streaming, no serving.

Default `connect()` endpoint: unix socket if it exists, else TCP.

## Binary identity encoding (verified) + remaining assumption

`identity` = a `bool` presence flag (`0x01`/`0x00`) then the 33-byte compressed
key *only when present* (null identity = a single `0x00`). Verified against a
live node's `host_info_msg` (`tests/test_codec.py::test_host_info_msg_matches_live_bytes`
pins the captured bytes). So an anonymous `route_query.Caller` is just `0x00`.

Still assumed (not yet confirmed against a node): `zone` = uint8 bitmask
(device=1, virtual=2, network=4, "dvn"=7). JSON transports avoid all of this. If
a real node disagrees, adjust `codec.identity` / `encoding.Zone` and `messages`
schemas, and use `examples/dump_handshake.py` to capture the real bytes.

## Testing

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

No pytest, no live node. `tests/test_integration_binary.py` and
`tests/test_websocket.py` spin up in-process mock servers that reuse the real
`Channel` classes. `tests/test_codec.py` pins the codecs to the doc byte
examples (`00000003010203`, `0575696e743815`, etc.) — keep those exact.

## Conventions

- stdlib only; no runtime deps. Sync API; serving uses daemon threads.
- New protocol helpers go in `api/` (one module per protocol, e.g. `api/dir.py`),
  wrap `client.call*`, return Python values, and attach as lazy properties on
  `Client`. Importing `api/<p>.py` registers that protocol's records.
- Structured wire types are `Record` subclasses declaring `TYPE` + `FIELDS` and
  decorated with `@register(type)`; they decode over binary and JSON alike.
- `ack`/`eos` may appear as `astral.ack` / `astral.eos`; use `obj.is_ack/is_eos`.
