"""The `ip` module client, and the `bytes8` address design risk R-12 names.

Three tiers in one file, because the same claim is made at each and the three
must agree:

- **Tier A** pins the wire and the two text functions. Every byte vector here is
  a byte the node sent: `ip.local_addrs`, `ip.default_gateway` and
  `objects.new?type=mod.ip.ip_address` on `furry-bolt`, captured raw. The text
  and predicate tables are **generated from Go 1.25.1**, not read off the source:
  `net.IP.String()` and the six predicates `api/ip/ip.go` exposes, evaluated over
  the byte patterns below and pinned. R-12 asks whether the payload is 4 or 16
  bytes and the answer is both, per family, which the live vectors settle.
- **Tier B** pins the three ops against `MockApphost`: the query string each one
  builds -- none of them carries a parameter -- the answer each accepts, and the
  two terminations, since `default_gateway` ends at a bare EOF and the other two
  end at an `eos`.
- **Tier C** runs all three against a real node. Every one is read-only.

The op inventory is the live `shell.spec` registry and nothing else:
`ip.default_gateway`, `ip.local_addrs` and `ip.public_ip_candidates`, verified
this session against `furry-bolt`. astral-go has no `ip` client at all.
"""

from __future__ import annotations

import asyncio
import json
import unittest

import astral
from astral.api import ip as ip_module
from astral.api.ip import (
    IPAddress,
    IP_TYPES,
    Ip,
    NetworkAddressChanged,
    OP_DEFAULT_GATEWAY,
    OP_LOCAL_ADDRS,
    OP_PUBLIC_IP_CANDIDATES,
)
from astral.blueprint import of as blueprint_of
from astral.client import connect
from astral.codec import decode, encode
from astral.codec.binary import object_reader, payload_bytes, read_object
from astral.codec.jsoncodec import marshal, unmarshal
from astral.codec.text import decode as text_decode
from astral.codec.text import encode as text_encode
from astral.errors import BadArgumentType, ParseError, ProtocolError, RemoteError
from astral.registry import default_blueprints
from astral.session import Session, flush_cancels
from astral.spec import Slice

import live_support
from mock_apphost import (
    Accept,
    ErrorMsg,
    MockApphost,
    bounded,
    frame,
    socket_fds,
)

# --- vectors, all of them bytes the node sent ----------------------------

# The whole body of `ip.local_addrs` on `furry-bolt`: two addresses and an
# `eos`. One IPv4 of four bytes and one IPv6 of sixteen, which is R-12 settled
# in one capture. The loopback is absent because the node excludes it.
LIVE_LOCAL_ADDRS_BODY = bytes.fromhex(
    "11" "6d6f642e69702e69705f61646472657373"  # string8 "mod.ip.ip_address"
    "00000005" "04" "0a150005"                 # bytes32 len, bytes8 len, 10.21.0.5
    "11" "6d6f642e69702e69705f61646472657373"
    "00000011" "10" "fe800000000000008aa29efffea84ab0"
    "03" "656f73" "00000000"                   # eos
)

# The whole body of `ip.default_gateway`: one address and then EOF. No `eos`
# anywhere in it, which is why nothing in this SDK waits for one.
LIVE_DEFAULT_GATEWAY_BODY = bytes.fromhex(
    "11" "6d6f642e69702e69705f61646472657373" "00000005" "04" "0a150001"
)

# The whole body of `ip.public_ip_candidates`: an `eos` and nothing else. An
# empty answer is the ordinary answer.
LIVE_EMPTY_CANDIDATES_BODY = bytes.fromhex("03656f7300000000")

# `objects.new?type=mod.ip.ip_address` builds the zero value server-side. One
# byte: a `bytes8` length of zero.
LIVE_ZERO_PAYLOAD = bytes.fromhex("00")

# `objects.new?type=mod.ip.events.network_address_changed`: three empty slices,
# three `uint32` counts of zero.
LIVE_EVENT_ZERO_PAYLOAD = bytes.fromhex("000000000000000000000000")

IPV4_PAYLOAD = bytes.fromhex("040a150005")
IPV6_PAYLOAD = bytes.fromhex("10fe800000000000008aa29efffea84ab0")
GATEWAY_PAYLOAD = bytes.fromhex("040a150001")

LOCAL_V4 = IPAddress(bytes.fromhex("0a150005"))
LOCAL_V6 = IPAddress(bytes.fromhex("fe800000000000008aa29efffea84ab0"))
GATEWAY = IPAddress(bytes.fromhex("0a150001"))

# `net.IP.String()` over twenty byte patterns, evaluated by Go 1.25.1 and
# pinned. The three rules that make this table and not the stdlib's rendering
# the specification: an empty value is `<nil>`, a length that is neither 4 nor
# 16 is `?` and hex, and an IPv4-mapped IPv6 address renders dotted.
GO_STRINGS = (
    ("", "<nil>"),
    ("0a150005", "10.21.0.5"),
    ("0a150001", "10.21.0.1"),
    ("7f000001", "127.0.0.1"),
    ("00000000", "0.0.0.0"),
    ("ffffffff", "255.255.255.255"),
    ("fe800000000000008aa29efffea84ab0", "fe80::8aa2:9eff:fea8:4ab0"),
    ("00000000000000000000ffff0a150005", "10.21.0.5"),
    ("00000000000000000000000000000000", "::"),
    ("20010db8000000000000000000000001", "2001:db8::1"),
    ("20010db8000000010000000000000000", "2001:db8:0:1::"),
    ("0000000000000000000000000a150005", "::a15:5"),
    # Two zero runs of equal length: Go keeps the first, and so does this.
    ("00010000000000010000000000010001", "1::1:0:0:1:1"),
    ("20010db8000000000001000000000001", "2001:db8::1:0:0:1"),
    ("0102030405060708090a0b0c0d0e0f10", "102:304:506:708:90a:b0c:d0e:f10"),
    ("0a1500", "?0a1500"),
    ("0a15000501", "?0a15000501"),
    ("00", "?00"),
    ("ff020000000000000000000000000001", "ff02::1"),
    ("20010db8853a000000008a2e03707334", "2001:db8:853a::8a2e:370:7334"),
)

# `net.ParseIP` over eighteen strings, evaluated by Go 1.25.1. `None` is what Go
# refuses. The hex is Go's in-memory form, which is sixteen bytes for an IPv4
# address; this type narrows it, and the wire bytes are the same either way
# because `IP.WriteTo` narrows too.
GO_PARSES = (
    ("1.2.3.4", "00000000000000000000ffff01020304"),
    ("10.21.0.5", "00000000000000000000ffff0a150005"),
    ("::ffff:1.2.3.4", "00000000000000000000ffff01020304"),
    ("::", "00000000000000000000000000000000"),
    ("0.0.0.0", "00000000000000000000ffff00000000"),
    ("fe80::1", "fe800000000000000000000000000001"),
    ("FE80::1", "fe800000000000000000000000000001"),
    ("fe80::1%eth0", None),
    ("010.1.1.1", None),
    (" 1.2.3.4", None),
    ("1.2.3.4/32", None),
    ("<nil>", None),
    ("?0a15000501", None),
    ("2001:db8::1", "20010db8000000000000000000000001"),
    ("1.2.3", None),
    ("::1", "00000000000000000000000000000001"),
    ("255.255.255.255", "00000000000000000000ffffffffffff"),
    ("0:0:0:0:0:0:0:1", "00000000000000000000000000000001"),
)

OWN_RENDERINGS = frozenset({"<nil>", "?0a15000501"})
"""The two rows of `GO_PARSES` this type deliberately parses and Go does not.

They are the output of `IPAddress.text()` for a value that is not an address, so
refusing them made the type's own encoder unreadable on the json and text
framings while binary and canonical carried it. The table stays as Go evaluated
it; the divergence is asserted by name in
`test_the_two_renderings_go_cannot_parse_are_read_back_here`."""

# `net.IP`'s predicates and astral-go's `IsPublic`, evaluated by Go 1.25.1 over
# thirty-one byte patterns. Column order: v4, loopback, private, global unicast,
# public, unspecified, multicast, link-local unicast.
GO_PREDICATES = (
    ("", 0, 0, 0, 0, 0, 0, 0, 0),
    ("00", 0, 0, 0, 0, 0, 0, 0, 0),
    ("0a1500", 0, 0, 0, 0, 0, 0, 0, 0),
    ("0a150005", 1, 0, 1, 1, 0, 0, 0, 0),
    ("0a150001", 1, 0, 1, 1, 0, 0, 0, 0),
    ("7f000001", 1, 1, 0, 0, 0, 0, 0, 0),
    ("7f0000ff", 1, 1, 0, 0, 0, 0, 0, 0),
    ("00000000", 1, 0, 0, 0, 0, 1, 0, 0),
    ("ffffffff", 1, 0, 0, 0, 0, 0, 0, 0),
    ("ac100001", 1, 0, 1, 1, 0, 0, 0, 0),
    ("ac1f0001", 1, 0, 1, 1, 0, 0, 0, 0),
    ("ac200001", 1, 0, 0, 1, 1, 0, 0, 0),
    ("c0a80001", 1, 0, 1, 1, 0, 0, 0, 0),
    ("c0a90001", 1, 0, 0, 1, 1, 0, 0, 0),
    ("08080808", 1, 0, 0, 1, 1, 0, 0, 0),
    ("01010101", 1, 0, 0, 1, 1, 0, 0, 0),
    ("a9fe0001", 1, 0, 0, 0, 0, 0, 0, 1),
    ("e0000001", 1, 0, 0, 0, 0, 0, 1, 0),
    # `100.64.0.1`, `192.0.0.1` and `192.0.2.1` are public to Go and private to
    # `ipaddress`, which is why the predicates here are not the stdlib's.
    ("64400001", 1, 0, 0, 1, 1, 0, 0, 0),
    ("c0000001", 1, 0, 0, 1, 1, 0, 0, 0),
    ("c0000201", 1, 0, 0, 1, 1, 0, 0, 0),
    ("fe800000000000008aa29efffea84ab0", 0, 0, 0, 0, 0, 0, 0, 1),
    ("00000000000000000000000000000001", 0, 1, 0, 0, 0, 0, 0, 0),
    ("00000000000000000000000000000000", 0, 0, 0, 0, 0, 1, 0, 0),
    ("fc000000000000000000000000000001", 0, 0, 1, 1, 0, 0, 0, 0),
    ("fd000000000000000000000000000001", 0, 0, 1, 1, 0, 0, 0, 0),
    ("fe000000000000000000000000000001", 0, 0, 0, 1, 1, 0, 0, 0),
    # `2001:db8::1` is documentation space: public to Go, private to `ipaddress`.
    ("20010db8000000000000000000000001", 0, 0, 0, 1, 1, 0, 0, 0),
    ("ff020000000000000000000000000001", 0, 0, 0, 0, 0, 0, 1, 0),
    ("26060000000000000000000000000001", 0, 0, 0, 1, 1, 0, 0, 0),
    ("0000000000000000000000000a150005", 0, 0, 0, 1, 1, 0, 0, 0),
)


ACK_FRAME = ("ack", b"")


def address_frame(address: IPAddress) -> tuple[str, bytes]:
    return ("mod.ip.ip_address", payload_bytes(address))


def error_frame(message: str) -> tuple[str, bytes]:
    from astral.wire import Writer

    w = Writer()
    w.string16(message)
    return ("error_message", w.getvalue())


# --- Tier A: the record, on the bytes the node sent ----------------------


class IPAddressWireTest(unittest.TestCase):
    """`mod.ip.ip_address` against the payloads `furry-bolt` produced."""

    def test_the_ipv4_payload_is_four_bytes_behind_a_length(self):
        """R-12's first half. `04` is the `bytes8` length and the four bytes are
        the address."""
        got = read_object(object_reader(IPV4_PAYLOAD), "mod.ip.ip_address")
        self.assertIsInstance(got, IPAddress)
        self.assertEqual(len(got), 4)
        self.assertEqual(got.text(), "10.21.0.5")
        self.assertEqual(payload_bytes(got), IPV4_PAYLOAD)

    def test_the_ipv6_payload_is_sixteen_bytes_behind_a_length(self):
        """R-12's second half, from the same capture as the first."""
        got = read_object(object_reader(IPV6_PAYLOAD), "mod.ip.ip_address")
        self.assertEqual(len(got), 16)
        self.assertEqual(got.text(), "fe80::8aa2:9eff:fea8:4ab0")
        self.assertEqual(payload_bytes(got), IPV6_PAYLOAD)

    def test_the_zero_value_the_node_built_is_one_null_byte(self):
        got = read_object(object_reader(LIVE_ZERO_PAYLOAD), "mod.ip.ip_address")
        self.assertEqual(got, IPAddress())
        self.assertTrue(got.is_zero())
        self.assertEqual(got.text(), "<nil>")
        self.assertEqual(payload_bytes(got), LIVE_ZERO_PAYLOAD)

    def test_the_zero_address_is_not_the_unspecified_address(self):
        """`<nil>` has no bytes; `0.0.0.0` has four. The wire tells them apart
        and so does this type."""
        self.assertTrue(IPAddress().is_zero())
        self.assertFalse(IPAddress().is_unspecified())
        unspecified = IPAddress(bytes(4))
        self.assertFalse(unspecified.is_zero())
        self.assertTrue(unspecified.is_unspecified())
        self.assertNotEqual(IPAddress(), unspecified)
        self.assertNotEqual(payload_bytes(IPAddress()), payload_bytes(unspecified))

    def test_the_whole_local_addrs_body_decodes_frame_by_frame(self):
        """The body is the two addresses and an `eos`, in that order."""
        self.assertEqual(
            LIVE_LOCAL_ADDRS_BODY,
            frame("mod.ip.ip_address", IPV4_PAYLOAD)
            + frame("mod.ip.ip_address", IPV6_PAYLOAD)
            + frame("eos"),
        )

    def test_the_default_gateway_body_carries_no_eos(self):
        """RR here, ST one op away: the shape is per-op and is not on the wire."""
        self.assertEqual(
            LIVE_DEFAULT_GATEWAY_BODY, frame("mod.ip.ip_address", GATEWAY_PAYLOAD)
        )
        self.assertNotIn(frame("eos"), LIVE_DEFAULT_GATEWAY_BODY)
        self.assertEqual(LIVE_EMPTY_CANDIDATES_BODY, frame("eos"))

    def test_a_length_that_is_neither_four_nor_sixteen_still_decodes(self):
        """astral-go's reader takes any `bytes8`, so a decoder that refused
        could not read what the reference can write."""
        odd = read_object(object_reader(bytes.fromhex("030a1500")), "mod.ip.ip_address")
        self.assertEqual(len(odd), 3)
        self.assertEqual(odd.text(), "?0a1500")
        self.assertEqual(payload_bytes(odd), bytes.fromhex("030a1500"))
        self.assertFalse(odd.is_ipv4())
        self.assertFalse(odd.is_ipv6())

    def test_an_ipv4_mapped_value_narrows_to_its_four_bytes(self):
        """astral-go narrows in `WriteTo`; this narrows at construction. The
        wire bytes are identical and one address gains one representation."""
        mapped = IPAddress(bytes.fromhex("00000000000000000000ffff0a150005"))
        self.assertEqual(len(mapped), 4)
        self.assertEqual(mapped, LOCAL_V4)
        self.assertEqual(payload_bytes(mapped), IPV4_PAYLOAD)

    def test_an_ipv4_compatible_value_is_not_narrowed(self):
        """`::a15:5` has ten zeros and `0000` where the mapped form has `ffff`.
        Go's `To4` refuses it and so does this."""
        compatible = IPAddress(bytes.fromhex("0000000000000000000000000a150005"))
        self.assertEqual(len(compatible), 16)
        self.assertEqual(compatible.text(), "::a15:5")

    def test_the_blueprint_is_alias_kind_over_bytes8(self):
        """The layout, and not the length rule: `astral.blueprint` cannot
        express one. The node derives no blueprint for this type at all --
        `objects.get_blueprint?type=mod.ip.ip_address` answers `BlueprintFromType:
        want struct or *struct, got ip.IP` -- so this is a deliberate divergence
        that describes the payload exactly, on the `bip137sig.entropy`
        precedent."""
        got = blueprint_of(IPAddress)
        self.assertEqual(got.underlying, "bytes8")
        self.assertEqual(list(got.fields), [])

    def test_the_type_is_registered_under_the_name_the_node_uses(self):
        self.assertTrue(default_blueprints().has("mod.ip.ip_address"))
        self.assertEqual(IPAddress.ASTRAL_TYPE, "mod.ip.ip_address")
        self.assertIsInstance(default_blueprints().new("mod.ip.ip_address"), IPAddress)


class TextFormTest(unittest.TestCase):
    """`text()` against `net.IP.String()`, generated rather than argued."""

    def test_every_go_rendering_is_reproduced(self):
        for hexed, want in GO_STRINGS:
            with self.subTest(hex=hexed):
                self.assertEqual(IPAddress(bytes.fromhex(hexed)).text(), want)

    def test_str_and_repr_go_through_the_one_text_function(self):
        """R-12 names two contradictory `_ip_str` helpers in the legacy SDK.
        There is one here and every rendering path reaches it."""
        self.assertEqual(str(LOCAL_V4), "10.21.0.5")
        self.assertEqual(repr(LOCAL_V4), "IPAddress('10.21.0.5')")
        self.assertEqual(repr(IPAddress()), "IPAddress('<nil>')")

    def test_every_go_parse_verdict_is_reproduced(self):
        for text, want in GO_PARSES:
            with self.subTest(text=text):
                if text in OWN_RENDERINGS:
                    # Accepted here and refused by Go: see the next test.
                    continue
                if want is None:
                    with self.assertRaises(ParseError):
                        IPAddress.parse(text)
                    continue
                got = IPAddress.parse(text)
                # Go keeps sixteen bytes for an IPv4 address in memory and
                # narrows in `WriteTo`; the comparison is on what reaches the
                # wire, which is where the two agree.
                self.assertEqual(
                    payload_bytes(got),
                    payload_bytes(IPAddress(bytes.fromhex(want))),
                )

    def test_the_two_renderings_go_cannot_parse_are_read_back_here(self):
        """`text()` has two spellings for a value that is not an address, Go's
        `net.ParseIP` refuses both, and this parser accepts both.

        The divergence is deliberate and it is the narrowest one that closes the
        format matrix: an unset address is legally constructible and is what
        `objects.new` answers, `nat.endpoint`, `nat.hole` and `nat.punch_signal`
        carry one through `Ref`, and while the refusal stood those records
        decoded on the binary and canonical framings and failed on json and
        text. Nothing else about the parser widens -- `010.1.1.1`, ` 1.2.3.4`
        and `1.2.3.4/32` are still refused, and `?zz` is not the `?` form."""
        for value in (IPAddress(), IPAddress(bytes.fromhex("0a1500"))):
            with self.subTest(value=value):
                self.assertEqual(IPAddress.parse(value.text()), value)
        self.assertEqual(IPAddress.parse("<nil>"), IPAddress())
        with self.assertRaises(ParseError):
            IPAddress.parse("?zz")

    def test_a_scope_id_is_refused_rather_than_dropped(self):
        with self.assertRaises(ParseError) as caught:
            IPAddress.parse("fe80::1%eth0")
        self.assertIn("scope id", str(caught.exception))

    def test_parse_refuses_a_value_that_is_not_text(self):
        """`ipaddress.ip_address(5)` is `0.0.0.5`, which nobody named."""
        for value in (5, b"1.2.3.4", None):
            with self.subTest(value=value):
                with self.assertRaises(ParseError):
                    IPAddress.parse(value)  # type: ignore[arg-type]

    def test_construction_takes_bytes_and_refuses_text(self):
        with self.assertRaises(BadArgumentType) as caught:
            IPAddress("10.21.0.5")  # type: ignore[arg-type]
        self.assertIn("parse()", str(caught.exception))
        with self.assertRaises(BadArgumentType):
            IPAddress(4)  # type: ignore[arg-type]

    def test_the_text_codec_round_trips_a_real_address(self):
        line = text_encode(LOCAL_V4)
        self.assertEqual(line, "#[mod.ip.ip_address] 10.21.0.5")
        self.assertEqual(text_decode(line), LOCAL_V4)

    def test_the_binary_codec_round_trips_a_real_address(self):
        self.assertEqual(decode(encode(LOCAL_V6)), LOCAL_V6)

    def test_the_json_form_is_the_text_form_as_a_string(self):
        self.assertEqual(marshal(LOCAL_V6), "fe80::8aa2:9eff:fea8:4ab0")
        self.assertEqual(unmarshal("mod.ip.ip_address", "10.21.0.5"), LOCAL_V4)
        with self.assertRaises(ParseError):
            unmarshal("mod.ip.ip_address", 42)

    def test_the_ipaddress_bridge_answers_for_a_real_address_only(self):
        import ipaddress as stdlib

        self.assertEqual(LOCAL_V4.address(), stdlib.IPv4Address("10.21.0.5"))
        self.assertEqual(
            LOCAL_V6.address(), stdlib.IPv6Address("fe80::8aa2:9eff:fea8:4ab0")
        )
        with self.assertRaises(ParseError):
            IPAddress().address()


class PredicateTest(unittest.TestCase):
    """The six questions astral-go's `IP` answers, against Go's answers."""

    def test_every_go_predicate_is_reproduced(self):
        for row in GO_PREDICATES:
            hexed = row[0]
            with self.subTest(hex=hexed):
                address = IPAddress(bytes.fromhex(hexed))
                got = (
                    int(address.is_ipv4()),
                    int(address.is_loopback()),
                    int(address.is_private()),
                    int(address.is_global_unicast()),
                    int(address.is_public()),
                    int(address.is_unspecified()),
                    int(address.is_multicast()),
                    int(address.is_link_local_unicast()),
                )
                self.assertEqual(got, row[1:])

    def test_the_families_are_exclusive_here_and_not_in_go(self):
        """Go's `IsIPv6` is `To16() != nil`, which an IPv4 address satisfies.
        This is the narrower question, so an address is one family or neither."""
        self.assertTrue(LOCAL_V4.is_ipv4())
        self.assertFalse(LOCAL_V4.is_ipv6())
        self.assertTrue(LOCAL_V6.is_ipv6())
        self.assertFalse(LOCAL_V6.is_ipv4())
        self.assertFalse(IPAddress().is_ipv4())
        self.assertFalse(IPAddress().is_ipv6())

    def test_to4_answers_the_bytes_or_nothing(self):
        self.assertEqual(LOCAL_V4.to4(), bytes.fromhex("0a150005"))
        self.assertIsNone(LOCAL_V6.to4())
        self.assertIsNone(IPAddress().to4())

    def test_the_local_addresses_the_node_returned_are_not_loopback(self):
        """`ip.local_addrs` excludes the loopback, verified live. The two it
        returned agree."""
        for address in (LOCAL_V4, LOCAL_V6):
            with self.subTest(address=address):
                self.assertFalse(address.is_loopback())
        self.assertTrue(IPAddress(bytes.fromhex("7f000001")).is_loopback())


class NetworkAddressChangedTest(unittest.TestCase):
    """The event type, registered for decode and sent by no `ip` op."""

    def test_the_zero_value_the_node_built_is_three_empty_counts(self):
        got = read_object(
            object_reader(LIVE_EVENT_ZERO_PAYLOAD),
            "mod.ip.events.network_address_changed",
        )
        self.assertEqual(got, NetworkAddressChanged())
        self.assertEqual(payload_bytes(got), LIVE_EVENT_ZERO_PAYLOAD)

    def test_the_field_declaration_matches_the_node_s_own_blueprint(self):
        """`objects.get_blueprint?type=mod.ip.events.network_address_changed`
        answers three `SliceSpec(mod.ip.ip_address)` named Removed, Added and
        All, verified live."""
        self.assertEqual(
            [(f.wire_name, f.spec) for f in NetworkAddressChanged.FIELDS],
            [
                ("Removed", Slice("mod.ip.ip_address")),
                ("Added", Slice("mod.ip.ip_address")),
                ("All", Slice("mod.ip.ip_address")),
            ],
        )

    def test_a_populated_event_round_trips(self):
        event = NetworkAddressChanged(
            removed=[LOCAL_V4], added=[LOCAL_V6], all=[LOCAL_V6, GATEWAY]
        )
        payload = payload_bytes(event)
        back = read_object(
            object_reader(payload), "mod.ip.events.network_address_changed"
        )
        self.assertEqual(back, event)
        self.assertEqual(payload_bytes(back), payload)


class IpTypesTest(unittest.TestCase):
    """The module's own inventory."""

    def test_the_type_sweep_names_every_declared_type(self):
        self.assertEqual(tuple(IP_TYPES), (IPAddress, NetworkAddressChanged))
        self.assertEqual(tuple(Ip.TYPES), tuple(IP_TYPES))

    def test_the_op_names_carry_no_mod_prefix(self):
        for op in (OP_DEFAULT_GATEWAY, OP_LOCAL_ADDRS, OP_PUBLIC_IP_CANDIDATES):
            with self.subTest(op=op):
                self.assertTrue(op.startswith("ip."))
                self.assertFalse(op.startswith("mod."))

    def test_the_module_declares_the_whole_live_op_surface(self):
        """Three ops, from the live registry. Nothing invented and nothing
        dropped."""
        self.assertEqual(
            {OP_DEFAULT_GATEWAY, OP_LOCAL_ADDRS, OP_PUBLIC_IP_CANDIDATES},
            {"ip.default_gateway", "ip.local_addrs", "ip.public_ip_candidates"},
        )

    def test_every_op_has_a_method(self):
        for op in (OP_DEFAULT_GATEWAY, OP_LOCAL_ADDRS, OP_PUBLIC_IP_CANDIDATES):
            with self.subTest(op=op):
                self.assertTrue(callable(getattr(Ip, op.split(".", 1)[1])))

    def test_the_module_is_imported_by_the_package(self):
        import sys

        import astral.api

        self.assertIn("astral.api.ip", sys.modules)
        self.assertIs(astral.api.ip, ip_module)
        self.assertIs(astral.api.Ip, Ip)


# --- Tier B: the three ops against a mock apphost ------------------------


class IpCase(unittest.IsolatedAsyncioTestCase):
    """An `Ip` over a mock apphost, closed by the teardown whatever a test
    does."""

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

    async def ip(self, mock: MockApphost, **kw: object) -> Ip:
        client = await connect(connector=self.connector(mock), **kw)  # type: ignore[arg-type]
        self.clients.append(client)
        return Ip(client)

    def sent(self, mock: MockApphost) -> str:
        self.assertEqual(len(mock.queries), 1, f"queries: {mock.queries}")
        return mock.queries[0].query

    def assert_no_faults(self, mock: MockApphost) -> None:
        self.assertEqual(mock.errors, [])


class LocalAddrsOpTest(IpCase):
    """`ip.local_addrs`: ST, ends at `eos`."""

    @bounded()
    async def test_it_returns_typed_addresses_and_sends_no_parameter(self):
        mock = MockApphost(
            routes={
                OP_LOCAL_ADDRS: Accept(
                    objects=[address_frame(LOCAL_V4), address_frame(LOCAL_V6)],
                    eos=True,
                )
            }
        )
        async with mock:
            got = await (await self.ip(mock)).local_addrs()
        self.assertEqual(got, [LOCAL_V4, LOCAL_V6])
        self.assertTrue(all(isinstance(a, IPAddress) for a in got))
        self.assertEqual(self.sent(mock), OP_LOCAL_ADDRS)
        self.assert_no_faults(mock)

    @bounded()
    async def test_it_ends_at_a_bare_eof_as_well_as_at_an_eos(self):
        mock = MockApphost(
            routes={OP_LOCAL_ADDRS: Accept(objects=[address_frame(GATEWAY)])}
        )
        async with mock:
            self.assertEqual(await (await self.ip(mock)).local_addrs(), [GATEWAY])

    @bounded()
    async def test_an_empty_answer_is_an_empty_list_and_not_a_fault(self):
        mock = MockApphost(routes={OP_LOCAL_ADDRS: Accept(eos=True)})
        async with mock:
            self.assertEqual(await (await self.ip(mock)).local_addrs(), [])
        self.assert_no_faults(mock)

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_LOCAL_ADDRS: Accept(objects=[ACK_FRAME], eos=True)})
        async with mock:
            with self.assertRaises(ProtocolError) as caught:
                await (await self.ip(mock)).local_addrs()
        self.assertIn(OP_LOCAL_ADDRS, str(caught.exception))
        self.assertIn("mod.ip.ip_address", str(caught.exception))

    @bounded()
    async def test_an_error_message_raises_rather_than_being_yielded(self):
        mock = MockApphost(
            routes={
                OP_LOCAL_ADDRS: Accept(objects=[error_frame("no interfaces")], eos=True)
            }
        )
        async with mock:
            with self.assertRaises(RemoteError):
                await (await self.ip(mock)).local_addrs()

    @bounded()
    async def test_it_leaves_no_stream_open(self):
        mock = MockApphost(routes={OP_LOCAL_ADDRS: Accept(eos=True)})
        async with mock:
            module = await self.ip(mock)
            await module.local_addrs()
            self.assertEqual(module.client.live_streams, 0)

    @bounded()
    async def test_the_query_keywords_reach_the_node(self):
        mock = MockApphost(routes={OP_LOCAL_ADDRS: Accept(eos=True)})
        async with mock:
            await (await self.ip(mock)).local_addrs(zone=astral.Zone.DEVICE)
        self.assertEqual(mock.queries[0].zone, int(astral.Zone.DEVICE))


class PublicIPCandidatesOpTest(IpCase):
    """`ip.public_ip_candidates`: ST, ends at `eos`, empty on this node."""

    @bounded()
    async def test_it_returns_typed_addresses(self):
        mock = MockApphost(
            routes={
                OP_PUBLIC_IP_CANDIDATES: Accept(
                    objects=[address_frame(GATEWAY)], eos=True
                )
            }
        )
        async with mock:
            got = await (await self.ip(mock)).public_ip_candidates()
        self.assertEqual(got, [GATEWAY])
        self.assertEqual(self.sent(mock), OP_PUBLIC_IP_CANDIDATES)

    @bounded()
    async def test_an_empty_answer_is_the_ordinary_answer(self):
        """`furry-bolt` answers a bare `eos`, verified live."""
        mock = MockApphost(routes={OP_PUBLIC_IP_CANDIDATES: Accept(eos=True)})
        async with mock:
            self.assertEqual(
                await (await self.ip(mock)).public_ip_candidates(), []
            )
        self.assert_no_faults(mock)

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(
            routes={OP_PUBLIC_IP_CANDIDATES: Accept(objects=[ACK_FRAME], eos=True)}
        )
        async with mock:
            with self.assertRaises(ProtocolError):
                await (await self.ip(mock)).public_ip_candidates()


class DefaultGatewayOpTest(IpCase):
    """`ip.default_gateway`: RR, no `eos`."""

    @bounded()
    async def test_it_returns_one_address(self):
        mock = MockApphost(
            routes={OP_DEFAULT_GATEWAY: Accept(objects=[address_frame(GATEWAY)])}
        )
        async with mock:
            got = await (await self.ip(mock)).default_gateway()
        self.assertEqual(got, GATEWAY)
        self.assertEqual(got.text(), "10.21.0.1")
        self.assertEqual(self.sent(mock), OP_DEFAULT_GATEWAY)
        self.assert_no_faults(mock)

    @bounded()
    async def test_a_second_object_raises_rather_than_being_dropped(self):
        mock = MockApphost(
            routes={
                OP_DEFAULT_GATEWAY: Accept(
                    objects=[address_frame(GATEWAY), address_frame(LOCAL_V4)]
                )
            }
        )
        async with mock:
            with self.assertRaises(ProtocolError):
                await (await self.ip(mock)).default_gateway()

    @bounded()
    async def test_an_error_message_surfaces_as_a_remote_error(self):
        """A node with no default route answers one."""
        mock = MockApphost(
            routes={OP_DEFAULT_GATEWAY: Accept(objects=[error_frame("no gateway")])}
        )
        async with mock:
            with self.assertRaises(RemoteError) as caught:
                await (await self.ip(mock)).default_gateway()
        self.assertIn("no gateway", str(caught.exception))

    @bounded()
    async def test_a_wrong_answer_type_is_a_protocol_error(self):
        mock = MockApphost(routes={OP_DEFAULT_GATEWAY: Accept(objects=[ACK_FRAME])})
        async with mock:
            with self.assertRaises(ProtocolError):
                await (await self.ip(mock)).default_gateway()

    @bounded()
    async def test_a_session_failure_surfaces_and_closes(self):
        mock = MockApphost(routes={OP_DEFAULT_GATEWAY: ErrorMsg("route_not_found")})
        async with mock:
            module = await self.ip(mock)
            with self.assertRaises(astral.errors.AstralError):
                await module.default_gateway()
            self.assertEqual(module.client.live_streams, 0)

    @bounded()
    async def test_it_leaves_no_stream_open(self):
        mock = MockApphost(
            routes={OP_DEFAULT_GATEWAY: Accept(objects=[address_frame(GATEWAY)])}
        )
        async with mock:
            module = await self.ip(mock)
            await module.default_gateway()
            self.assertEqual(module.client.live_streams, 0)


class ClientAttachmentTest(IpCase):
    """`client.ip`, the property design section 5.1 gives every ops module."""

    @bounded()
    async def test_the_property_is_cached_and_bound(self):
        async with MockApphost() as mock:
            client = await connect(connector=self.connector(mock))
            self.clients.append(client)
            self.assertIsInstance(client.ip, Ip)
            self.assertIs(client.ip, client.ip)
            self.assertIs(client.ip.client, client)


# --- Tier C: the read-only ops against a real node -----------------------


class LiveIpTest(live_support.LiveCase):
    """`ip` against a real node. Every op here is read-only.

    The three probes that are not `ip` ops -- `shell.spec` and two
    `objects.new` -- are on the anonymous read-only list and are what settle the
    op surface and the zero value against the node rather than against a copy of
    it.
    """

    @bounded(30.0)
    async def test_the_module_s_op_surface_is_exactly_these_three(self):
        async with await self.client() as client:
            body = await client.call_raw("shell.spec?out=json", timeout=20.0)
        names = {
            json.loads(line)["Object"]["Name"]
            for line in body.decode().splitlines()
            if line and json.loads(line)["Type"] == "routing.op_spec"
        }
        self.assertEqual(
            {name for name in names if name.startswith("ip.")},
            {OP_DEFAULT_GATEWAY, OP_LOCAL_ADDRS, OP_PUBLIC_IP_CANDIDATES},
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_no_op_declares_a_parameter_of_its_own(self):
        """`in` and `out` are the channel formats every op carries. Nothing else
        is declared, which is why no method here takes an argument."""
        async with await self.client() as client:
            params = {}
            for op in (OP_DEFAULT_GATEWAY, OP_LOCAL_ADDRS, OP_PUBLIC_IP_CANDIDATES):
                body = await client.call_raw(
                    f"shell.spec?op={op}&out=json", timeout=20.0
                )
                spec = json.loads(body.decode().splitlines()[0])["Object"]
                params[op] = [
                    (p["Name"], p["Type"], p["Required"]) for p in spec["Parameters"]
                ]
        self.assertEqual(
            params[OP_DEFAULT_GATEWAY], [("out", "string8", False)]
        )
        self.assertEqual(
            params[OP_LOCAL_ADDRS],
            [("in", "string8", False), ("out", "string8", False)],
        )
        self.assertEqual(
            params[OP_PUBLIC_IP_CANDIDATES], [("out", "string8", False)]
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_local_addrs_answers_addresses_of_four_or_sixteen_bytes(self):
        """R-12 settled against the node rather than against a vector of it."""
        async with await self.client() as client:
            got = await client.ip.local_addrs(timeout=20.0)
        self.assertIsInstance(got, list)
        self.assertTrue(got, "the node reported no local address at all")
        for address in got:
            with self.subTest(address=address):
                self.assertIsInstance(address, IPAddress)
                self.assertIn(len(address), (4, 16))
                self.assertTrue(address.is_ipv4() or address.is_ipv6())
                # The loopback is excluded by the node.
                self.assertFalse(address.is_loopback())
                # The text form is a rendering of the same bytes.
                self.assertEqual(
                    payload_bytes(IPAddress.parse(address.text())),
                    payload_bytes(address),
                )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_local_addrs_body_ends_in_one_eos(self):
        async with await self.client() as client:
            body = await client.call_raw(OP_LOCAL_ADDRS, timeout=20.0)
        self.assertTrue(body.endswith(frame("eos")), body.hex())
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_default_gateway_answers_one_address_and_no_eos(self):
        """The op-mode difference, off the raw body rather than off the decoded
        object: RR here, ST one op away, and neither is discoverable from the
        wire."""
        async with await self.client() as client:
            body = await client.call_raw(OP_DEFAULT_GATEWAY, timeout=20.0)
            got = await client.ip.default_gateway(timeout=20.0)
        self.assertFalse(body.endswith(frame("eos")), body.hex())
        self.assertEqual(body, frame("mod.ip.ip_address", payload_bytes(got)))
        self.assertIsInstance(got, IPAddress)
        self.assertIn(len(got), (4, 16))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_public_ip_candidates_answers_a_list_that_may_be_empty(self):
        async with await self.client() as client:
            got = await client.ip.public_ip_candidates(timeout=20.0)
        self.assertIsInstance(got, list)
        for address in got:
            with self.subTest(address=address):
                self.assertIsInstance(address, IPAddress)
                self.assertIn(len(address), (4, 16))
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_the_node_builds_the_zero_value_this_module_builds(self):
        """`objects.new` constructs server-side, so the byte it answers is the
        node's own encoding of the zero address."""
        async with await self.client() as client:
            body = await client.call_raw(
                "objects.new?type=mod.ip.ip_address", timeout=20.0
            )
            event = await client.call_raw(
                "objects.new?type=mod.ip.events.network_address_changed", timeout=20.0
            )
        self.assertEqual(body, frame("mod.ip.ip_address", LIVE_ZERO_PAYLOAD))
        self.assertEqual(payload_bytes(IPAddress()), LIVE_ZERO_PAYLOAD)
        self.assertEqual(
            event,
            frame(
                "mod.ip.events.network_address_changed", LIVE_EVENT_ZERO_PAYLOAD
            ),
        )
        self.assertEqual(
            payload_bytes(NetworkAddressChanged()), LIVE_EVENT_ZERO_PAYLOAD
        )
        await self.assert_no_open_sockets()

    @bounded(30.0)
    async def test_one_session_answers_every_op(self):
        """Three ops on one client, because the node serves apphost from a pool
        of 32 workers shared with every app on the machine."""
        async with await self.client() as client:
            module = client.ip
            async with asyncio.timeout(25):
                await module.local_addrs(timeout=20.0)
                await module.public_ip_candidates(timeout=20.0)
                await module.default_gateway(timeout=20.0)
            self.assertEqual(client.live_streams, 0)
        await self.assert_no_open_sockets()


if __name__ == "__main__":
    unittest.main()
