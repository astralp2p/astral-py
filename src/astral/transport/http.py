"""HTTP transport: simple request/response queries returning JSON lines.

Reference: ``topics/http-transport.md``. The query string is the request path,
the target goes in ``X-Astral-Target``, auth is a bearer token, and the
response body is newline-delimited JSON objects in the *JSON Encoding*. HTTP is
request/response only — no input streaming and no serving inbound queries.
"""

from __future__ import annotations

import http.client
import json
from typing import Any, List, Optional

from ..encoding import build_query_string, from_json_envelope
from ..errors import ConnectError, NotSupported, ProtocolError
from ..objects import AstralObject
from ..stream import Stream
from .base import UNSET, Channel, Endpoint, HostInfo, Transport

__all__ = ["HttpTransport", "HttpResponseChannel"]

_DEFAULT_TIMEOUT = 30.0


class HttpResponseChannel(Channel):
    """A read-only channel backed by one HTTP response body."""

    def __init__(self, conn: http.client.HTTPConnection, response: http.client.HTTPResponse) -> None:
        self._conn = conn
        self._response = response
        self.status = response.status
        self.host_identity = response.getheader("X-Astral-Host-Identity", "") or ""
        self.guest_identity = response.getheader("X-Astral-Guest-Identity", "") or ""
        self._closed = False

    def send(self, item: Any) -> None:
        raise NotSupported("the HTTP transport cannot send objects on a stream")

    def recv(self) -> Optional[AstralObject]:
        while True:
            line = self._response.readline()
            if not line:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
            except ValueError as exc:
                text = line.decode("utf-8", "replace")
                if self.status >= 400:
                    raise ProtocolError(
                        f"HTTP {self.status}: {text}"
                    ) from exc
                raise ProtocolError(f"invalid JSON line: {text}") from exc
            return from_json_envelope(envelope)

    def recv_bytes(self, size: int = -1) -> bytes:
        if size < 0:
            return self._response.read()
        return self._response.read(size)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._response.close()
        except Exception:
            pass
        try:
            self._conn.close()
        except Exception:
            pass


class HttpTransport(Transport):
    """Issues one HTTP request per query against the apphost HTTP listener."""

    supports_serving = False

    def __init__(
        self,
        endpoint: Endpoint,
        token: Optional[str],
        *,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(endpoint, token)
        self.timeout = timeout
        self._secure = endpoint.scheme == "https"

    def _new_conn(self) -> http.client.HTTPConnection:
        host, port = self.endpoint.host_port if self.endpoint.address else ("localhost", 8624)
        cls = http.client.HTTPSConnection if self._secure else http.client.HTTPConnection
        return cls(host, port, timeout=self.timeout)

    def _request(self, query_string: str, target: Optional[str] = None) -> HttpResponseChannel:
        conn = self._new_conn()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if target:
            headers["X-Astral-Target"] = target
        path = "/" + query_string.lstrip("/")
        try:
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
        except OSError as exc:
            conn.close()
            raise ConnectError(f"HTTP request to {path!r} failed: {exc}") from exc
        return HttpResponseChannel(conn, response)

    def connect(self) -> HostInfo:
        channel = self._request("apphost.whoami")
        self.host = HostInfo(
            identity=channel.host_identity,
            alias=self.host.alias,
            guest_id=channel.guest_identity,
        )
        channel.close()
        return self.host

    def query(
        self,
        query_string: str,
        *,
        target: Optional[str] = None,
        caller: Any = UNSET,
        zone: Any = "dvn",
        filters: Optional[List[str]] = None,
    ) -> Stream:
        # caller/zone/filters have no HTTP representation; the authenticated
        # token determines the caller and the host applies default zones.
        channel = self._request(query_string, target=target)
        if not self.host.identity and channel.host_identity:
            self.host = HostInfo(channel.host_identity, self.host.alias, channel.guest_identity)
        return Stream(channel)

    def close(self) -> None:
        pass
