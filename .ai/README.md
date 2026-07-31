# AI context — astral-py

Vendor-neutral AI context for astral-py, the asyncio client for the astrald
**apphost IPC** protocol. Distribution `astral-ipc`, import package `astral`.

`CLAUDE.md` at the repository root is the working contract — the three layers
and the arrow between them, the wire facts that were expensive to establish, op
modes, connection hygiene, the test tiers. `docs/architecture.md` is the binding
specification it cites. This file is orientation, and the `system/` submodule is
the protocol spec at a pinned commit.

## Roles

- `README.md` — this file: orientation and what `system/` is for
- `system/` — the astral-docs corpus at a pinned commit

## Authority

`CLAUDE.md` sets the precedence order, and vendoring the spec here does not
change it:

1. The live node
2. astral-go, at the commit the node pins
3. astrald
4. `system/` (astral-docs)

Where the docs disagree with the node, **the node wins** and the disagreement is
a bug report in design section 9.2. **A wire fact sourced from `system/` alone is
not established.** The D-numbered defects cited throughout `tests/` — D-9, D-13,
D-23, D-24 among them — are that failure mode caught in the act: each is a place
the spec said one thing and a running node did another.

So `system/` is here for what it is reliable at — the protocol's shape and
vocabulary. Op inventories, type definitions, the narrative topics, the names
things are called. It is not a wire authority for this SDK, and a byte layout
read from it is a hypothesis until the node or astral-go confirms it.

`tests/reference.py` is unaffected: it pins astrald and astral-go by revision and
reads them with `git show`, and it does not read `system/`. Adding this submodule
changes what an assistant can consult, not what the suite verifies.

## Spec map

- Wire mechanics: `system/topics/` — `astral-ipc.md`, `binary-encoding.md`,
  `json-encoding.md`, `text-encoding.md`, `codec.md`, `op-modes.md`.
- Vocabulary: `system/core-definitions/` — object, object id, op, query, zone,
  channel, and the rest of the nouns.
- Common types: `system/primitive-types/` — one file per primitive, the widths
  among them.
- Per-protocol ops and types: `system/protocols/<name>/`, `ops/` and `types/`
  subdirectories.

Pinned at a specific commit, and moved deliberately: a bump means re-reading what
the pin was cited for, the same discipline `tests/reference.py` documents for the
astrald and astral-go pins.
