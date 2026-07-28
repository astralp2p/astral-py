"""The `exonet` endpoint abstraction and its network-name registry.

The module with no ops, so there is no Tier B here: nothing to send and nothing
to answer. What there is instead:

- **Tier A** pins the abstraction. `Endpoint` is astral-go's interface, the
  registry is astrald's dispatch table, and both are asserted against the four
  concrete types `endpoints.py` registers -- because an ABC with no subclass
  asserts nothing.
- **Tier C** asks the node one question this file exists to settle:
  `mod.exonet.endpoint` is not a type name at all. A Go interface has no
  `ObjectType()`, so `objects.new` answers `nil` and this module registers no
  wire type.

The registry is tested through a **private** `EndpointTypes` wherever a test
mutates one. The process-wide registry is filled at import by `endpoints.py` and
a test that registered into it would leak into every later test in the run.
"""

from __future__ import annotations

import abc
import inspect
import unittest

from astral.api import endpoints as endpoints_module
from astral.api import exonet as exonet_module
from astral.api.endpoints import (
    GatewayEndpoint,
    KcpEndpoint,
    TcpEndpoint,
    TorDigest,
    TorEndpoint,
)
from astral.api.exonet import (
    EXONET_TYPES,
    Endpoint,
    EndpointTypes,
    NETWORK_SEPARATOR,
    endpoint_types,
    parse_endpoint,
    unpack_endpoint,
)
from astral.api.ip import IPAddress
from astral.codec.binary import payload_bytes
from astral.errors import BadArgument
from astral.registry import default_blueprints

import live_support
from mock_apphost import bounded

TCP = TcpEndpoint(ip=IPAddress.parse("10.21.0.5"), port=8625)
TCP6 = TcpEndpoint(ip=IPAddress.parse("fe80::1"), port=8625)
KCP = KcpEndpoint(ip=IPAddress.parse("10.21.0.5"), port=8625)
DIGEST = TorDigest(bytes(range(35)))
TOR = TorEndpoint(digest=DIGEST, port=1791)


class EndpointAbstractionTest(unittest.TestCase):
    """`exonet.Endpoint`: astral-go's interface, as an abstract base class."""

    def test_the_interface_is_the_three_go_declares(self):
        """`Network()`, `Address()` and `Pack()`, plus `astral.Object`. Nothing
        else is on the interface and nothing else is required of a subclass."""
        self.assertTrue(issubclass(Endpoint, abc.ABC))
        self.assertEqual(
            sorted(Endpoint.__abstractmethods__), ["address", "network"]
        )
        for name in ("network", "address", "pack", "qualified"):
            with self.subTest(method=name):
                self.assertTrue(callable(getattr(Endpoint, name)))

    def test_it_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            Endpoint()  # type: ignore[abstract]

    def test_every_concrete_endpoint_is_one(self):
        for endpoint in (TCP, KCP, TOR, GatewayEndpoint()):
            with self.subTest(endpoint=type(endpoint).__name__):
                self.assertIsInstance(endpoint, Endpoint)

    def test_a_digest_is_not_an_endpoint(self):
        """`mod.tor.digest` is a component of one and has no network of its
        own."""
        self.assertNotIsInstance(DIGEST, Endpoint)

    def test_the_abstraction_adds_no_instance_dictionary(self):
        """`__slots__` is empty on the base, so a `@record` subclass keeps its
        own slots."""
        self.assertEqual(Endpoint.__slots__, ())
        self.assertFalse(hasattr(TCP, "__dict__"))

    def test_pack_is_the_object_payload_and_nothing_else(self):
        """astral-go's `Pack()` is `WriteTo` into a buffer: no type tag, no
        length prefix."""
        for endpoint in (TCP, TCP6, KCP, TOR, GatewayEndpoint()):
            with self.subTest(endpoint=type(endpoint).__name__):
                self.assertEqual(endpoint.pack(), payload_bytes(endpoint))

    def test_qualified_is_the_network_and_the_address(self):
        self.assertEqual(TCP.qualified(), "tcp:10.21.0.5:8625")
        self.assertEqual(TCP6.qualified(), "tcp:[fe80::1]:8625")
        self.assertEqual(KCP.qualified(), "kcp:10.21.0.5:8625")
        self.assertEqual(TOR.qualified(), f"tor:{TOR.address()}")
        self.assertEqual(NETWORK_SEPARATOR, ":")

    def test_the_network_is_fixed_per_class_and_never_an_alias(self):
        """`inet` is a registration name. No value ever reports it."""
        self.assertEqual(TCP.network(), "tcp")
        self.assertEqual(TcpEndpoint().network(), "tcp")
        self.assertEqual(KCP.network(), "kcp")
        self.assertEqual(TOR.network(), "tor")
        self.assertEqual(GatewayEndpoint().network(), "gw")

    def test_this_module_declares_no_wire_type(self):
        """A Go interface has no `ObjectType()`. `objects.new?type=
        mod.exonet.endpoint` answers `nil`, verified live."""
        self.assertEqual(tuple(EXONET_TYPES), ())
        self.assertFalse(default_blueprints().has("mod.exonet.endpoint"))

    def test_this_module_declares_no_module_client(self):
        """No ops, so no `ModuleClient` and no `client.exonet`."""
        from astral.api.base import ModuleClient
        from astral.client import Client

        clients = [
            value
            for value in vars(exonet_module).values()
            if inspect.isclass(value)
            and issubclass(value, ModuleClient)
            and value.__module__ == exonet_module.__name__
        ]
        self.assertEqual(clients, [])
        self.assertFalse(hasattr(Client, "exonet"))


class EndpointTypesTest(unittest.TestCase):
    """The network-name registry, on a private instance."""

    def setUp(self) -> None:
        self.types = EndpointTypes()

    def test_a_class_registers_under_its_own_network_name(self):
        self.types.register(TcpEndpoint)
        self.assertEqual(self.types.networks(), ["tcp"])
        self.assertIs(self.types.get("tcp"), TcpEndpoint)
        self.assertIsNone(self.types.get("inet"))

    def test_an_alias_is_an_extra_name_for_the_same_class(self):
        self.types.register(TcpEndpoint, "inet")
        self.assertEqual(self.types.networks(), ["inet", "tcp"])
        self.assertIs(self.types.get("inet"), TcpEndpoint)
        self.assertEqual(self.types.classes(), [TcpEndpoint])
        self.assertEqual(len(self.types), 2)

    def test_a_name_already_taken_is_refused(self):
        """A silent replacement makes which module imported last decide what
        `tcp:` means."""
        self.types.register(TcpEndpoint)
        with self.assertRaises(BadArgument) as caught:
            self.types.register(TcpEndpoint)
        self.assertIn("already registered", str(caught.exception))

    def test_a_refused_registration_leaves_the_table_as_it_was(self):
        """Every name is checked before any is inserted."""
        self.types.register(TcpEndpoint, "inet")
        with self.assertRaises(BadArgument):
            self.types.register(KcpEndpoint, "inet")
        self.assertEqual(self.types.networks(), ["inet", "tcp"])
        self.assertIs(self.types.get("inet"), TcpEndpoint)

    def test_an_empty_network_name_is_refused(self):
        with self.assertRaises(BadArgument):
            self.types.register(TcpEndpoint, "")

    def test_an_unregistered_network_names_itself_and_the_registered_ones(self):
        self.types.register(TcpEndpoint)
        with self.assertRaises(BadArgument) as caught:
            self.types.parse("utp", "1.2.3.4:80")
        self.assertIn("utp", str(caught.exception))
        self.assertIn("tcp", str(caught.exception))
        with self.assertRaises(BadArgument):
            self.types.unpack("utp", b"")

    def test_the_membership_and_iteration_surface(self):
        self.types.register(TcpEndpoint, "inet")
        self.assertIn("tcp", self.types)
        self.assertNotIn("kcp", self.types)
        self.assertEqual(list(self.types), ["inet", "tcp"])
        self.assertIn("tcp", repr(self.types))

    def test_parse_reads_the_address_through_the_class(self):
        self.types.register(TcpEndpoint, "inet")
        self.assertEqual(self.types.parse("tcp", "10.21.0.5:8625"), TCP)
        self.assertEqual(self.types.parse("inet", "10.21.0.5:8625"), TCP)

    def test_unpack_reads_the_payload_through_the_class(self):
        self.types.register(TcpEndpoint)
        self.assertEqual(self.types.unpack("tcp", TCP.pack()), TCP)

    def test_the_qualified_form_splits_on_the_first_separator_only(self):
        """An IPv6 address holds more of them and is still one address."""
        self.types.register(TcpEndpoint)
        self.assertEqual(self.types.parse_qualified("tcp:10.21.0.5:8625"), TCP)
        self.assertEqual(self.types.parse_qualified("tcp:[fe80::1]:8625"), TCP6)

    def test_a_form_with_no_separator_is_refused(self):
        self.types.register(TcpEndpoint)
        with self.assertRaises(BadArgument) as caught:
            self.types.parse_qualified("10.21.0.5")
        self.assertIn("<network>", str(caught.exception))

    def test_a_bare_address_is_refused_as_an_unknown_network(self):
        """`10.21.0.5:8625` has a separator, so the first half is read as the
        network and the fault names it. The two refusals are different
        sentences because they are different mistakes."""
        self.types.register(TcpEndpoint)
        with self.assertRaises(BadArgument) as caught:
            self.types.parse_qualified("10.21.0.5:8625")
        self.assertIn("unsupported network '10.21.0.5'", str(caught.exception))


class DefaultRegistryTest(unittest.TestCase):
    """The process-wide registry, which `endpoints.py` fills at import."""

    def test_the_four_shipped_types_are_registered(self):
        self.assertEqual(
            endpoint_types().networks(), ["gw", "inet", "kcp", "tcp", "tor"]
        )
        self.assertEqual(
            endpoint_types().classes(),
            [TcpEndpoint, KcpEndpoint, TorEndpoint, GatewayEndpoint],
        )

    def test_importing_astral_api_is_what_fills_it(self):
        """The counterpart of `default_blueprints()`: no caller has to know
        which module registered what."""
        import astral

        self.assertIs(astral.api.endpoint_types(), endpoint_types())
        self.assertIs(astral.api.endpoints, endpoints_module)

    def test_the_module_functions_reach_the_default_registry(self):
        self.assertEqual(parse_endpoint("tcp:10.21.0.5:8625"), TCP)
        self.assertEqual(parse_endpoint("inet:10.21.0.5:8625"), TCP)
        self.assertEqual(parse_endpoint("kcp:10.21.0.5:8625"), KCP)
        self.assertEqual(unpack_endpoint("tcp", TCP.pack()), TCP)

    def test_every_registered_type_round_trips_through_both_directions(self):
        """Parse the qualified form, pack it, unpack it: one value throughout."""
        for endpoint in (TCP, TCP6, KCP, TOR):
            with self.subTest(endpoint=endpoint.qualified()):
                parsed = parse_endpoint(endpoint.qualified())
                self.assertEqual(parsed, endpoint)
                self.assertEqual(
                    unpack_endpoint(endpoint.network(), parsed.pack()), endpoint
                )

    def test_an_unregistered_network_is_refused_by_name(self):
        """`mod.utp.endpoint` is not on this node: `objects.new` answers `nil`,
        verified live. Nothing here invents it."""
        with self.assertRaises(BadArgument) as caught:
            parse_endpoint("utp:1.2.3.4:80")
        self.assertIn("utp", str(caught.exception))


class LiveExonetTest(live_support.LiveCase):
    """The one question a node can settle about a module with no ops."""

    @bounded(30.0)
    async def test_the_interface_is_not_a_registered_type_on_the_node(self):
        """A Go interface has no `ObjectType()`, so the node has no blueprint
        for it and `objects.new` answers `nil`. That is why `EXONET_TYPES` is
        empty."""
        from mock_apphost import frame

        async with await self.client() as client:
            body = await client.call_raw(
                "objects.new?type=mod.exonet.endpoint", timeout=20.0
            )
        self.assertEqual(body, frame("nil"))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_answers_every_network_this_registry_knows(self):
        """Each registered network's type exists on the node. `objects.new`
        builds a zero value server-side, so a `nil` here would mean this SDK
        registered a network whose type the node does not have."""
        from mock_apphost import frame

        async with await self.client() as client:
            for cls in endpoint_types().classes():
                name = cls.ASTRAL_TYPE  # type: ignore[attr-defined]
                with self.subTest(type=name):
                    body = await client.call_raw(
                        f"objects.new?type={name}", timeout=20.0
                    )
                    self.assertNotEqual(body, frame("nil"), name)
                    self.assertEqual(body, frame(name, payload_bytes(cls())))
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
