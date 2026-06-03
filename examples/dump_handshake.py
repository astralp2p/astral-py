#!/usr/bin/env python3
"""Dump the raw bytes the node sends on a fresh binary apphost connection.

This is a diagnostic for binary-transport wire-format issues. It connects with
a plain socket (independent of the library's codec), reads whatever the host
pushes (the ``host_info_msg``), and prints the bytes plus a best-effort
breakdown of the channel frame and its payload.

    python examples/dump_handshake.py                 # default local endpoint
    python examples/dump_handshake.py unix:~/.apphost.sock
    python examples/dump_handshake.py tcp:127.0.0.1:8625
"""

from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from astral.transport.base import default_endpoint, parse_endpoint


def hexdump(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)


def main() -> int:
    endpoint = parse_endpoint(sys.argv[1]) if len(sys.argv) > 1 else default_endpoint()
    print(f"endpoint: {endpoint.scheme}:{endpoint.address}")

    if endpoint.scheme == "unix":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect(endpoint.address)
    elif endpoint.scheme == "tcp":
        host, port = endpoint.host_port
        sock = socket.create_connection((host, port), timeout=3.0)
    else:
        print("this diagnostic is for binary endpoints (unix:/tcp:) only", file=sys.stderr)
        return 2

    sock.settimeout(1.5)
    buf = b""
    try:
        while len(buf) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    finally:
        sock.close()

    print(f"\nreceived {len(buf)} bytes:")
    print(hexdump(buf))

    # Best-effort channel-frame parse: string8(type) ++ bytes32(payload)
    if len(buf) < 5:
        print("\n(too short to parse a frame)")
        return 0
    type_len = buf[0]
    obj_type = buf[1 : 1 + type_len]
    off = 1 + type_len
    payload_len = int.from_bytes(buf[off : off + 4], "big")
    off += 4
    payload = buf[off : off + payload_len]
    print(f"\nframe:")
    print(f"  type   : {obj_type.decode('latin1')!r} ({type_len} bytes)")
    print(f"  payload: {payload_len} bytes")
    print(f"  payload hex: {hexdump(payload)}")
    trailing = buf[off + payload_len :]
    if trailing:
        print(f"  trailing (next frame?): {hexdump(trailing)}")

    # Interpret the payload assuming a uint8-length-prefixed identity.
    if payload:
        idlen = payload[0]
        ident = payload[1 : 1 + idlen]
        rest = payload[1 + idlen :]
        print(f"\nif identity is uint8-length-prefixed:")
        print(f"  identity len : {idlen}")
        print(f"  identity hex : {ident.hex()}")
        if rest:
            alias_len = rest[0]
            alias = rest[1 : 1 + alias_len]
            print(f"  alias len    : {alias_len}")
            print(f"  alias        : {alias.decode('utf-8', 'replace')!r}")
            extra = rest[1 + alias_len :]
            if extra:
                print(f"  extra payload: {hexdump(extra)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
