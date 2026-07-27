"""`MemTransport`: an in-process duplex byte stream.

The point of this transport is to exercise the framing layer and the session
state machine with no kernel involved, so it is a faithful byte stream rather
than a convenient shortcut. Faithful means:

- a read returns whatever has arrived, up to the requested count, and never
  waits for the rest -- `max_chunk` forces the pathological case, one byte per
  read, on demand;
- `read()` returns `b""` at end of stream, and `readexactly()` raises `EOFError`
  at a clean close and `IncompleteRead` on a truncation, exactly as
  `StreamTransport` does;
- `write_eof()` half-closes: the peer drains what was already written, then sees
  EOF, and the read direction stays open;
- `aclose()` delivers bytes already written and then EOF, because a closed socket
  still delivers what the kernel accepted. That is what makes "close mid-frame"
  reproducible;
- a second concurrent reader raises `RuntimeError`, as `asyncio.StreamReader`
  does, rather than quietly taking the other reader's bytes;
- writing to a departed peer succeeds once and raises `ConnectionResetError`
  after that, which is what loopback does.

The last two are the ones that make this a test *oracle* rather than a
convenience: a defect the socket refuses must not pass here.

`MemTransport` is not wire-compatible with astral-go's `memconn`, so `memu:` and
`memb:` endpoints stay undialable (design section 3.1). Its endpoint string is
`mem:<name>`, descriptive only.

Every `write()` call is recorded in `writes`. The one-write-per-frame invariant
of design section 3.2 rule 2 is asserted against that list, so no separate spy
transport exists.
"""

from __future__ import annotations

import asyncio

from .base import IncompleteRead, Transport

__all__ = ["MemTransport"]


class _Pipe:
    """One direction of a pair: a byte buffer, an EOF flag and a wakeup."""

    __slots__ = ("_buf", "_eof", "_gone", "_dropped", "_waiting", "_wakeup")

    def __init__(self) -> None:
        self._buf = bytearray()
        self._eof = False
        self._gone = False
        self._dropped = False
        self._waiting = False
        self._wakeup = asyncio.Event()

    @property
    def buffered(self) -> int:
        return len(self._buf)

    @property
    def at_eof(self) -> bool:
        return self._eof and not self._buf

    def feed(self, data: bytes) -> None:
        """Append bytes, or report the peer's departure the way a socket does.

        Measured on loopback rather than assumed: the **first** write after the
        peer closed succeeds -- the bytes reach the kernel, which only then gets
        an RST back -- and every write after that raises `ConnectionResetError`.
        A pipe that silently swallowed all of them would let a test pass over
        memory and fail over a socket, which is the one thing this transport
        exists to prevent.
        """
        if not data:
            # An empty write is a no-op on a socket and costs no credit here.
            return
        if self._gone:
            if self._dropped:
                raise ConnectionResetError("the peer has gone away")
            self._dropped = True
            return
        self._buf += data
        self._wakeup.set()

    def feed_eof(self) -> None:
        """The sender is done. Buffered bytes are still readable."""
        self._eof = True
        self._wakeup.set()

    def abandon(self) -> None:
        """The reader is gone. Unread bytes are discarded."""
        self._gone = True
        self._eof = True
        self._buf.clear()
        self._wakeup.set()

    def take(self, n: int, max_chunk: int | None) -> bytes:
        limit = len(self._buf) if n < 0 else min(n, len(self._buf))
        if max_chunk is not None:
            limit = min(limit, max_chunk)
        out = bytes(self._buf[:limit])
        del self._buf[:limit]
        return out

    async def wait_readable(self) -> None:
        """Return once bytes are buffered or the stream has ended.

        One waiting reader at a time, which is not tidiness but fidelity:
        `asyncio.StreamReader` raises `RuntimeError` when a second coroutine
        waits on the same stream, and a pipe that instead handed each reader a
        different frame would let a concurrency defect pass here and fail on a
        socket.
        """
        while not self._buf and not self._eof:
            if self._waiting:
                raise RuntimeError(
                    "read() called while another coroutine is already waiting "
                    "for incoming data"
                )
            self._waiting = True
            try:
                self._wakeup.clear()
                await self._wakeup.wait()
            finally:
                self._waiting = False


class MemTransport(Transport):
    """A byte stream over two in-process buffers."""

    __slots__ = ("_in", "_out", "_endpoint", "_closed", "_wrote_eof", "_max_chunk", "writes")

    def __init__(
        self,
        read_pipe: _Pipe,
        write_pipe: _Pipe,
        endpoint: str = "mem:pair",
        *,
        max_chunk: int | None = None,
    ) -> None:
        self._in = read_pipe
        self._out = write_pipe
        self._endpoint = endpoint
        self._closed = False
        self._wrote_eof = False
        self._max_chunk = max_chunk
        # Test instrumentation: one entry per `write()` call, in call order.
        self.writes: list[bytes] = []

    # --- construction ---

    @classmethod
    def pair(
        cls,
        name: str = "pair",
        *,
        max_chunk: int | None = None,
        peer_max_chunk: int | None = None,
    ) -> tuple["MemTransport", "MemTransport"]:
        """Two transports joined back to back.

        `max_chunk` bounds every read on the first transport, `peer_max_chunk`
        every read on the second, so either side can be starved a byte at a time.
        """
        left, right = _Pipe(), _Pipe()
        endpoint = f"mem:{name}"
        return (
            cls(left, right, endpoint, max_chunk=max_chunk),
            cls(right, left, endpoint, max_chunk=peer_max_chunk),
        )

    @classmethod
    def solo(
        cls, name: str = "solo", *, max_chunk: int | None = None
    ) -> "MemTransport":
        """A transport with no peer, driven by `feed()` and read back via `sent`."""
        return cls(_Pipe(), _Pipe(), f"mem:{name}", max_chunk=max_chunk)

    # --- test instrumentation ---

    def feed(self, data: bytes) -> None:
        """Push bytes into this transport's own read side."""
        self._in.feed(data)

    def feed_eof(self) -> None:
        """End this transport's own read side."""
        self._in.feed_eof()

    @property
    def sent(self) -> bytes:
        """Every byte this transport has written, concatenated."""
        return b"".join(self.writes)

    @property
    def buffered(self) -> int:
        """Bytes waiting to be read."""
        return self._in.buffered

    # --- Transport ---

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def closed(self) -> bool:
        return self._closed

    async def readexactly(self, n: int) -> bytes:
        if n < 0:
            raise ValueError(f"negative read length {n}")
        if n == 0:
            return b""
        out = bytearray()
        while len(out) < n:
            chunk = await self.read(n - len(out))
            if not chunk:
                if not out:
                    raise EOFError("stream closed")
                raise IncompleteRead(bytes(out), n)
            out += chunk
        return bytes(out)

    async def read(self, n: int = -1) -> bytes:
        if n == 0:
            return b""
        if n < 0:
            out = bytearray()
            while True:
                await self._in.wait_readable()
                if self._in.at_eof:
                    return bytes(out)
                out += self._in.take(-1, None)
        await self._in.wait_readable()
        return self._in.take(n, self._max_chunk)

    def write(self, data: bytes) -> None:
        if self._closed or self._wrote_eof:
            raise ConnectionResetError(f"{self._endpoint}: transport is closed")
        payload = bytes(data)
        # Fed first: a write the peer's departure refuses is not a write, and
        # `writes` is what the one-write-per-frame invariant is asserted against.
        self._out.feed(payload)
        self.writes.append(payload)

    async def drain(self) -> None:
        if self._closed:
            raise ConnectionResetError(f"{self._endpoint}: transport is closed")

    def write_eof(self) -> None:
        if self._closed:
            raise ConnectionResetError(f"{self._endpoint}: transport is closed")
        if self._wrote_eof:
            return
        self._wrote_eof = True
        self._out.feed_eof()

    async def aclose(self) -> None:
        """Close both pipes. Returning means closed, for every caller.

        No wait for a concurrent closer is needed and none is written: there is
        no `await` between the flag and the last line, so the whole close runs
        inside one loop iteration and no second caller can observe a half-closed
        transport. `StreamTransport` needs an event because its flush is
        genuinely suspended; a guard here would be ceremony around nothing.
        """
        if self._closed:
            return
        self._closed = True
        # Bytes already written stay readable by the peer, then EOF. Unread
        # inbound bytes are discarded, matching a closed socket.
        self._out.feed_eof()
        self._in.abandon()
