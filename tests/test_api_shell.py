"""The `shell` module client: the node's own op registry, decoded.

Three tiers on one claim, because the claim is what the whole inventory rests
on:

- **Tier A** pins the wire. Every string in `routing.op_spec` and its nested
  `query.field_spec` is a bare Go `string` inside a reflectively-encoded struct,
  so every one is `string32` (design section 9.2, D-9). The vectors are frames
  captured from `furry-bolt`'s own `shell.spec`, and reading one length as a
  `string8` takes the first byte of a four-byte length for the whole length and
  desynchronises every field after it. `tests/test_risk_register.py::
  R14OpSpecStringWidth` decodes the same bytes through the same shipped types
  from the risk register's side.
- **Tier B** pins the op against `MockApphost`: the query string, the ST shape
  ending at `eos`, and the refusal of an answer of the wrong type.
- **Tier C** runs it against a real node. This is the op the SDK's own inventory
  came from, so the live assertion is the inventory's: the node answers more
  than a hundred specs anonymously, and every op this SDK sends is one of them.

Read-only and anonymous throughout: `shell.spec` touches no node state and needs
no token, which is what makes it usable as a self-check.
"""

from __future__ import annotations

import unittest

import astral
from astral.api.shell import FIELD_SPEC_TYPE, FieldSpec, OP_SPEC, OpSpec, Shell
from astral.client import connect
from astral.codec.binary import object_reader, payload_bytes, read_object
from astral.errors import ProtocolError
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels

import live_support
from mock_apphost import (
    Accept,
    MockApphost,
    bounded,
    frame,
    socket_fds,
)

# The first frame of `shell.spec` on `furry-bolt`, captured this session: one op
# with one parameter. Every length below is four bytes wide.
APPHOST_BIND = bytes.fromhex(
    "0000000c" "617070686f73742e62696e64"  # string32 Name "apphost.bind"
    "00000001"  # uint32 Parameters count
    "01"  # synthesized presence byte on a slice element
    "00000003" "6f7574"  # string32 Name "out"
    "00000007" "737472696e6738"  # string32 Type "string8"
    "00"  # bool Required
)

# Three parameters, and the one op whose `id` is a `nonce64`.
APPHOST_CANCEL = bytes.fromhex(
    "0000000e" "617070686f73742e63616e63656c"
    "00000003"
    "01" "00000002" "6964" "00000007" "6e6f6e63653634" "00"
    "01" "00000005" "6361757365" "00000007" "737472696e6738" "00"
    "01" "00000003" "6f7574" "00000007" "737472696e6738" "00"
)

# One op with a parameter the node **enforces**: `Required` is 0x01 only where
# the server's argument struct carries a `query:"required"` tag.
REQUIRED_SPEC = bytes.fromhex(
    "0000000d" "6469722e7365745f616c696173"  # "dir.set_alias"
    "00000001"
    "01" "00000005" "616c696173" "00000007" "737472696e6738" "01"
)

SPEC_FRAME = frame("routing.op_spec", APPHOST_BIND)
CANCEL_FRAME = frame("routing.op_spec", APPHOST_CANCEL)


class OpSpecWireTest(unittest.TestCase):
    """Tier A: the captured bytes, through the shipped declarations."""

    def test_the_first_length_is_four_bytes_and_not_one(self):
        """D-9 in one assertion. A `string8` reader takes `0x00` for the whole
        length and every field after it decodes as something else."""
        spec = read_object(object_reader(APPHOST_BIND), "routing.op_spec")
        self.assertEqual(spec.name, "apphost.bind")
        self.assertEqual(APPHOST_BIND[:4], b"\x00\x00\x00\x0c")

    def test_a_captured_spec_round_trips_byte_for_byte(self):
        for payload in (APPHOST_BIND, APPHOST_CANCEL, REQUIRED_SPEC):
            with self.subTest(payload=payload[:8].hex()):
                spec = read_object(object_reader(payload), "routing.op_spec")
                self.assertEqual(payload_bytes(spec), payload)

    def test_the_parameters_decode_with_their_types(self):
        spec = read_object(object_reader(APPHOST_CANCEL), "routing.op_spec")
        self.assertEqual(
            [(p.name, p.type) for p in spec.parameters],
            [("id", "nonce64"), ("cause", "string8"), ("out", "string8")],
        )
        self.assertEqual(spec.param("id").type, "nonce64")
        self.assertIsNone(spec.param("ID"), "matching is case-sensitive")
        self.assertIsNone(spec.param("nope"))

    def test_required_is_the_enforced_set_and_not_the_documented_one(self):
        """`Required` comes from a `query:"required"` struct tag alone, so most
        parameters the docs call required carry none."""
        self.assertEqual(
            read_object(object_reader(APPHOST_CANCEL), "routing.op_spec")
            .required_params(),
            [],
        )
        self.assertEqual(
            read_object(object_reader(REQUIRED_SPEC), "routing.op_spec")
            .required_params(),
            ["alias"],
        )

    def test_the_module_half_of_a_name_is_reported(self):
        spec = read_object(object_reader(APPHOST_BIND), "routing.op_spec")
        self.assertEqual(spec.module, "apphost")
        self.assertEqual(OpSpec(name="bare", parameters=[]).module, "")

    def test_the_field_spec_type_is_registered_and_the_node_never_sends_it(self):
        """astral-go never calls `astral.Add` on `query.FieldSpec`, so nothing on
        the wire carries this tag; it is declared because a `Slice` names its
        element type and the registry resolves that name."""
        self.assertTrue(default_blueprints().has(FIELD_SPEC_TYPE))
        self.assertEqual(FieldSpec.ASTRAL_TYPE, FIELD_SPEC_TYPE)
        self.assertEqual(str(FieldSpec(name="out", type="string8", required=False)),
                         "out:string8")
        self.assertEqual(str(FieldSpec(name="alias", type="string8", required=True)),
                         "alias:string8*")


class ShellCase(unittest.IsolatedAsyncioTestCase):
    """A `Shell` over a mock apphost, closed by the teardown whatever a test does."""

    async def asyncSetUp(self) -> None:
        self.clients: list[astral.Client] = []
        self.sockets_before = socket_fds()

    async def asyncTearDown(self) -> None:
        for client in self.clients:
            await client.aclose()
        await flush_cancels(5.0)

    def connector(self, mock: MockApphost):  # type: ignore[no-untyped-def]
        async def open_session() -> Session:
            return await Session.over(
                await mock.open(), endpoint="mem:mock", connector=open_session
            )

        return open_session

    async def shell(self, mock: MockApphost, **kw: object) -> Shell:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Shell(client)


class SpecOpTest(ShellCase):
    """Tier B: `shell.spec` is ST and ends at an `eos`."""

    @bounded()
    async def test_it_returns_every_spec_the_node_sent(self):
        mock = MockApphost(
            routes={OP_SPEC: Accept(objects=[
                ("routing.op_spec", APPHOST_BIND),
                ("routing.op_spec", APPHOST_CANCEL),
            ], eos=True)}
        )
        async with mock:
            specs = await (await self.shell(mock)).spec()
        self.assertEqual([s.name for s in specs], ["apphost.bind", "apphost.cancel"])
        self.assertEqual([q.query for q in mock.queries], [OP_SPEC])
        self.assertEqual(mock.errors, [])

    @bounded()
    async def test_ops_is_the_same_answer_keyed_by_name(self):
        mock = MockApphost(
            routes={OP_SPEC: Accept(objects=[
                ("routing.op_spec", APPHOST_BIND),
                ("routing.op_spec", APPHOST_CANCEL),
            ], eos=True)}
        )
        async with mock:
            ops = await (await self.shell(mock)).ops()
        self.assertEqual(sorted(ops), ["apphost.bind", "apphost.cancel"])
        self.assertEqual(ops["apphost.cancel"].param("cause").type, "string8")

    @bounded()
    async def test_an_empty_registry_is_an_empty_list_and_not_a_hang(self):
        mock = MockApphost(routes={OP_SPEC: Accept(eos=True)})
        async with mock:
            self.assertEqual(await (await self.shell(mock)).spec(), [])

    @bounded()
    async def test_an_answer_of_the_wrong_type_is_a_protocol_error(self):
        """A wrong type is the remote breaking its own contract, so it is a
        `ProtocolError` and never a decode fault the caller has to interpret."""
        mock = MockApphost(routes={OP_SPEC: Accept(objects=[("ack", b"")], eos=True)})
        async with mock:
            with self.assertRaises(ProtocolError):
                await (await self.shell(mock)).spec()


class ClientAttachmentTest(unittest.TestCase):
    def test_the_client_reaches_it_as_a_property(self):
        """Design section 1's package layout and section 0.1's op count both name
        this module; the property is what makes it reachable."""
        self.assertTrue(hasattr(astral.Client, "shell"))


class LiveShellTest(live_support.LiveCase):
    """Tier C: the op the SDK's own inventory was read off.

    Anonymous and read-only. Design section 7.3 lists `shell.spec` in the live
    op set for exactly this: it is the one query that can check the SDK against
    the node it is talking to.
    """

    @bounded(60.0)
    async def test_the_node_answers_its_whole_registry_anonymously(self):
        async with await self.client() as client:
            specs = await client.shell.spec()
        self.assertGreater(len(specs), 100, "the survey counted 118 on this node")
        self.assertTrue(all(isinstance(s, OpSpec) for s in specs))
        names = {s.name for s in specs}
        # Four ops from four modules, one of them the op itself.
        for op in ("shell.spec", "apphost.whoami", "dir.alias_map", "objects.scan"):
            with self.subTest(op=op):
                self.assertIn(op, names)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_every_spec_re_encodes_to_the_bytes_the_node_sent(self):
        """The byte-exact half: a decode this SDK accepts must re-encode to what
        arrived, or the width rule is wrong somewhere in the 118."""
        async with await self.client() as client:
            async with client.stream(f"{OP_SPEC}?out=bin", raw=True) as stream:
                data = await stream.read_bytes(timeout=15.0)
        from astral.wire import Reader

        r = Reader(data)
        seen = 0
        while r.remaining:
            type_name = r.string8()
            payload = r.bytes32()
            if type_name == "eos":
                break
            self.assertEqual(type_name, OpSpec.ASTRAL_TYPE)
            self.assertEqual(payload_bytes(read_object(object_reader(payload),
                                                       OpSpec.ASTRAL_TYPE)), payload)
            seen += 1
        self.assertGreater(seen, 100)
        await self.assert_no_open_sockets()

    @bounded(60.0)
    async def test_every_op_this_sdk_sends_exists_on_the_node(self):
        """The self-check the module exists for. Each module client's op-name
        constants are compared against the node's own registry, so an op renamed
        upstream fails here rather than at a caller's first use."""
        async with await self.client() as client:
            ops = await client.shell.ops()
        missing = sorted(name for name in _sdk_op_names() if name not in ops)
        self.assertEqual(missing, [], "ops the SDK sends that the node does not have")
        await self.assert_no_open_sockets()


def _sdk_op_names() -> set[str]:
    """Every `OP_*` constant every `astral.api` module declares."""
    import pkgutil

    import astral.api

    names: set[str] = set()
    for info in pkgutil.iter_modules(astral.api.__path__):
        module = __import__(f"astral.api.{info.name}", fromlist=["*"])
        for attr in dir(module):
            if not attr.startswith("OP_"):
                continue
            value = getattr(module, attr)
            # `.` and no `mod.` prefix: an op name, not a type name.
            if isinstance(value, str) and "." in value and not value.startswith("mod."):
                names.add(value)
    return names


if __name__ == "__main__":
    unittest.main()
