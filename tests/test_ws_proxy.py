# tests/test_ws_proxy.py
#
# Offline unit tests for the wRFC HTTP CONNECT proxy tunnel (D-16 step 2 / D-20).
#
# _open_proxy_tunnel is exercised against a scripted in-memory socket double that
# returns canned CONNECT responses (200 opens, 407 raises). No network.
#
# Security invariants under test:
#   - T-07-PROXY-CRED: the proxy password never appears in a raised WebSocketError.
#   - Proxy-Authorization uses base64(user:pass) UTF-8 (RFC 7617).

import base64

import pytest

from saprfclib.exceptions import WebSocketError
from saprfclib.ws import _open_proxy_tunnel


class ScriptedSocket:
    """Minimal socket double: records sendall() bytes, replays a canned response.

    recv() returns the scripted response in chunks so the tunnel reader must loop.
    """

    def __init__(self, response: bytes, *, chunk: int = 4096) -> None:
        self.sent = bytearray()
        self._response = bytes(response)
        self._pos = 0
        self._chunk = chunk

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, bufsize: int) -> bytes:
        if self._pos >= len(self._response):
            return b""  # EOF
        end = min(self._pos + min(bufsize, self._chunk), len(self._response))
        out = self._response[self._pos : end]
        self._pos = end
        return out


def test_connect_tunnel_opens_on_200() -> None:
    sock = ScriptedSocket(b"HTTP/1.1 200 Connection established\r\n\r\n")
    # Should not raise.
    _open_proxy_tunnel(sock, "sap.example.com", 443)
    assert b"CONNECT sap.example.com:443 HTTP/1.1" in bytes(sock.sent)
    assert b"Host: sap.example.com:443" in bytes(sock.sent)


def test_connect_tunnel_sends_basic_auth_base64() -> None:
    sock = ScriptedSocket(b"HTTP/1.1 200 Connection established\r\n\r\n")
    _open_proxy_tunnel(sock, "sap.example.com", 443, user="alice", password="s3cr3t")
    expected = base64.b64encode(b"alice:s3cr3t").decode()
    assert f"Proxy-Authorization: Basic {expected}".encode("ascii") in bytes(sock.sent)


def test_connect_tunnel_raises_on_407() -> None:
    sock = ScriptedSocket(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"
    )
    with pytest.raises(WebSocketError):
        _open_proxy_tunnel(sock, "sap.example.com", 443, user="alice", password="s3cr3t")


def test_connect_407_error_never_leaks_password() -> None:
    password = "topsecret-do-not-log"
    sock = ScriptedSocket(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
    with pytest.raises(WebSocketError) as exc:
        _open_proxy_tunnel(sock, "sap.example.com", 443, user="alice", password=password)
    text = str(exc.value) + repr(exc.value)
    assert password not in text
    # The status code SHOULD be surfaced for debuggability.
    assert "407" in text


def test_connect_tunnel_reports_status_only_no_credentials() -> None:
    # Even a generic 502 must not echo any credential material.
    password = "another-secret"
    sock = ScriptedSocket(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    with pytest.raises(WebSocketError) as exc:
        _open_proxy_tunnel(sock, "sap.example.com", 443, user="bob", password=password)
    assert password not in (str(exc.value) + repr(exc.value))
