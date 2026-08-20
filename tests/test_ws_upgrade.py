# tests/test_ws_upgrade.py
#
# Offline unit tests for the RFC 6455 WebSocket upgrade handshake (D-16 steps 4-5)
# and the single-redirect rule (D-21). No network: a scripted in-memory socket
# double replays canned HTTP responses; the client-side upgrade drives wsproto.
#
# Contract under test:
#   - Sec-WebSocket-Accept validation: base64(SHA1(key + RFC 6455 GUID)).
#     A correct accept succeeds; a wrong accept raises WebSocketError.
#   - A 302 with a Location header is followed exactly once (D-21); a second 3xx
#     raises WebSocketError.
#   - A non-101 / non-3xx response raises WebSocketError.
#   - Only SSLContext.wrap_socket is used (grep guard in test_ws_frames.py).

import base64
import hashlib

import pytest

from saprfclib.exceptions import WebSocketError
from saprfclib.ws import _GUID, _ws_upgrade


def _accept_for(key: bytes) -> str:
    return base64.b64encode(hashlib.sha1(key + _GUID).digest()).decode()


class ScriptedUpgradeSocket:
    """Socket double that captures the client's GET and replays a 101/3xx/other.

    ``response_factory`` is called with the Sec-WebSocket-Key the client sent
    (extracted from the captured request) so the fixture can compute a correct
    (or deliberately wrong) Sec-WebSocket-Accept. A list of factories drives
    multi-hop (redirect) scenarios: each new _ws_upgrade GET pops the next one.
    """

    def __init__(self, response_factories, *, extra_after: bytes = b"") -> None:
        self._factories = list(response_factories)
        self._extra_after = extra_after
        self.sent = bytearray()
        self._pending = bytearray()
        self._hop = 0
        self.request_lines: list[bytes] = []  # first line of each GET (per hop)

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)
        # A request ends at the blank line; when we see it, arm the next response.
        if b"\r\n\r\n" in bytes(self.sent):
            self.request_lines.append(bytes(self.sent).split(b"\r\n", 1)[0])
            key = self._extract_key(bytes(self.sent))
            factory = self._factories[self._hop]
            self._hop += 1
            resp = factory(key)
            # On the final (successful) hop, append any post-101 leftover bytes.
            if self._hop == len(self._factories):
                resp = resp + self._extra_after
            self._pending.extend(resp)
            # Reset for the next hop's request capture.
            self.sent = bytearray()

    @staticmethod
    def _extract_key(request: bytes) -> bytes:
        for line in request.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                return line.split(b":", 1)[1].strip()
        raise AssertionError("client did not send Sec-WebSocket-Key")

    def recv(self, bufsize: int) -> bytes:
        if not self._pending:
            return b""
        n = min(bufsize, len(self._pending))
        out = bytes(self._pending[:n])
        del self._pending[:n]
        return out


def _resp_101(key: bytes) -> bytes:
    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + _accept_for(key).encode("ascii") + b"\r\n\r\n"
    )


def _resp_101_wrong_accept(key: bytes) -> bytes:
    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: not-the-right-accept-value\r\n\r\n"
    )


def _resp_302(location: bytes):
    def factory(key: bytes) -> bytes:
        return b"HTTP/1.1 302 Found\r\nLocation: " + location + b"\r\nContent-Length: 0\r\n\r\n"

    return factory


def _resp_500(key: bytes) -> bytes:
    return b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"


def test_upgrade_succeeds_with_correct_accept() -> None:
    sock = ScriptedUpgradeSocket([_resp_101])
    leftover = _ws_upgrade(sock, host="sap.example.com", port=443, ws_path="/sap/bc/rfc")
    # No trailing frame bytes in this scenario.
    assert leftover in (b"", None)


def test_upgrade_rejects_wrong_accept() -> None:
    sock = ScriptedUpgradeSocket([_resp_101_wrong_accept])
    with pytest.raises(WebSocketError):
        _ws_upgrade(sock, host="sap.example.com", port=443, ws_path="/sap/bc/rfc")


def test_upgrade_returns_leftover_frame_bytes() -> None:
    trailing = b"\x82\x03abc"  # a stray binary frame arriving glued to the 101
    sock = ScriptedUpgradeSocket([_resp_101], extra_after=trailing)
    leftover = _ws_upgrade(sock, host="sap.example.com", port=443, ws_path="/sap/bc/rfc")
    assert leftover == trailing


def test_upgrade_follows_single_302_redirect() -> None:
    sock = ScriptedUpgradeSocket([_resp_302(b"wss://sap.example.com/new/path"), _resp_101])
    leftover = _ws_upgrade(sock, host="sap.example.com", port=443, ws_path="/sap/bc/rfc")
    assert leftover in (b"", None)
    # Exactly two GETs were sent; the second targeted the redirected path (D-21).
    assert len(sock.request_lines) == 2
    assert sock.request_lines[0] == b"GET /sap/bc/rfc HTTP/1.1"
    assert sock.request_lines[1] == b"GET /new/path HTTP/1.1"


def test_upgrade_raises_on_second_redirect() -> None:
    sock = ScriptedUpgradeSocket(
        [_resp_302(b"wss://sap.example.com/a"), _resp_302(b"wss://sap.example.com/b")]
    )
    with pytest.raises(WebSocketError):
        _ws_upgrade(sock, host="sap.example.com", port=443, ws_path="/sap/bc/rfc")


def test_upgrade_raises_on_500() -> None:
    sock = ScriptedUpgradeSocket([_resp_500])
    with pytest.raises(WebSocketError):
        _ws_upgrade(sock, host="sap.example.com", port=443, ws_path="/sap/bc/rfc")
