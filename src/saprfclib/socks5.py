# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — SOCKS5 proxy transport for raw RFC/TCP (issue #51, D-39/40/41)
#
# Opens a TCP connection to a target SAP gateway *through* a SOCKS5 proxy — the
# interface the SAP BTP Connectivity Proxy exposes so that Kubernetes/Kyma
# workloads can reach on-premise systems via SAP Cloud Connector without the
# NW RFC SDK, the Transparent Proxy, or a local socat bridge.
#
#     saprfclib → SOCKS5 proxy (:20004) → Cloud Connector → vhost:3300 → SAP
#
# This module is sans-I/O at its core: every wire value is built and parsed by a
# pure function (build_* / parse_*), and the two thin I/O entry points
# (socks5_connect / socks5_connect_async) only move those bytes across a socket.
# SOCKS5 sits *below* the NI length prefix, so the Session/RFC layer above is
# untouched — the returned socket is handed to the ordinary Transport.
#
# ─ Authentication (D-40) ─────────────────────────────────────────────────────
# SAP uses exactly two SOCKS5 authentication methods. It does NOT implement the
# RFC 1929 username/password method (0x02):
#
#   * 0x00 "no authentication" (RFC 1928 §3) — the Connectivity Proxy in
#     *trusted mode* (``config.servers.proxy.socks5.enableProxyAuthorization =
#     false``, the default for in-cluster Kyma workloads). The proxy derives the
#     subaccount from the caller's in-cluster identity, so no token is sent.
#   * 0x80 SAP custom JWT method — the Cloud Foundry Connectivity service SOCKS5
#     proxy (where authentication is mandatory) and the Connectivity Proxy in
#     *untrusted mode*. A JWT access token (optionally plus a Cloud Connector
#     location id) is sent in a SAP-specific sub-negotiation frame.
#
# Source for the 0x80 frame layout and the method number: SAP's own published
# connectivity documentation (CC-BY 4.0), file
# ``using-the-tcp-protocol-for-cloud-applications-cd15837.md`` in the
# SAP-docs/btp-connectivity repository — the Markdown behind the help.sap.com
# page "Using the TCP Protocol for Cloud Applications" — together with SAP's
# reference sample ``ConnectivitySocks5ProxySocket``. Confirmed-on-doc, pending
# live confirmation against a Kyma Connectivity Proxy (issue #51). The 0x00 path
# and the CONNECT request/reply are plain RFC 1928.
#
# ─ Security (threat T-07-PROXY-CRED, D-41) ───────────────────────────────────
# The JWT, the OAuth client_secret and any proxy password are used only to build
# wire bytes. They are NEVER placed into a log record or an exception message. A
# failure reports the SOCKS5 reply code and its meaning — never the token.
from __future__ import annotations

import asyncio
import base64
import json
import socket
import struct
import urllib.error
import urllib.request
from collections.abc import Sequence

from saprfclib.exceptions import ProxyError
from saprfclib.transport import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    enable_keepalive,
)

__all__ = [
    "SOCKS_VERSION",
    "AUTH_NONE",
    "AUTH_SAP_JWT",
    "AUTH_NO_ACCEPTABLE",
    "build_greeting",
    "parse_method_selection",
    "build_jwt_auth",
    "parse_jwt_auth_reply",
    "build_connect",
    "parse_connect_reply",
    "socks5_connect",
    "socks5_connect_async",
    "fetch_connectivity_token",
]

# RFC 1928 §3-§4 constants.
SOCKS_VERSION = 0x05
CMD_CONNECT = 0x01
_RSV = 0x00
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Authentication method numbers.
AUTH_NONE = 0x00  # RFC 1928 §3: "NO AUTHENTICATION REQUIRED".
AUTH_SAP_JWT = 0x80  # SAP custom method. Source: SAP-docs cd15837 (X'80').
AUTH_NO_ACCEPTABLE = 0xFF  # RFC 1928 §3: server rejects every offered method.

# SAP JWT sub-negotiation. Source: SAP-docs cd15837 / ConnectivitySocks5ProxySocket.
_JWT_SUBNEG_VERSION = 0x01  # "Authentication method version - currently 1".
_AUTH_SUCCESS = 0x00  # SOCKS5_AUTHENTICATION_SUCCESS_BYTE.

# CONNECT reply codes (RFC 1928 §6). The text matches SAP's own translation in
# ConnectivitySocks5ProxySocket so a failure here reads the same as it would from
# the reference client.
_REP_MEANING = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed (forbidden)",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}

# Mirror the NI-layer frame cap: a SOCKS5 handshake is a few hundred bytes, so a
# multi-kilobyte declared field is a malformed or hostile peer, not a real reply.
_MAX_REPLY_FIELD = 4096


# --------------------------------------------------------------------------- #
# Sans-I/O: greeting / method selection                                       #
# --------------------------------------------------------------------------- #
def build_greeting(methods: Sequence[int]) -> bytes:
    """Build the SOCKS5 greeting (RFC 1928 §3): VER, NMETHODS, METHODS.

    ``methods`` are the authentication method numbers the client offers, e.g.
    ``[AUTH_NONE]`` for trusted-mode Connectivity Proxy or ``[AUTH_SAP_JWT]`` for
    the SAP JWT method.
    """
    if not methods or len(methods) > 255:
        raise ValueError("SOCKS5 greeting needs between 1 and 255 methods")
    return bytes((SOCKS_VERSION, len(methods), *methods))


def parse_method_selection(data: bytes) -> int:
    """Parse the server's method-selection reply (RFC 1928 §3): VER, METHOD.

    Returns the selected method number. Raises :class:`ProxyError` if the version
    is wrong or the server answered 0xFF ("no acceptable methods").
    """
    if len(data) != 2:
        raise ProxyError(f"SOCKS5 method selection must be 2 bytes, got {len(data)}")
    version, method = data[0], data[1]
    if version != SOCKS_VERSION:
        raise ProxyError(f"SOCKS5 version mismatch: expected 0x05, got {version:#04x}")
    if method == AUTH_NO_ACCEPTABLE:
        raise ProxyError(
            "SOCKS5 proxy rejected every offered authentication method (0xFF). "
            "If the proxy requires SAP JWT authentication, supply proxy_jwt or the "
            "proxy_client_id/proxy_client_secret/proxy_token_url triple"
        )
    return method


# --------------------------------------------------------------------------- #
# Sans-I/O: SAP JWT sub-negotiation (method 0x80)                              #
# --------------------------------------------------------------------------- #
def build_jwt_auth(jwt: str, scc_location_id: str = "") -> bytes:
    """Build the SAP JWT authentication sub-negotiation request (method 0x80).

    Wire layout, source SAP-docs cd15837 (and the ConnectivitySocks5ProxySocket
    sample):

        1 byte   sub-negotiation version (0x01)
        4 bytes  JWT length, uint32 big-endian
        X bytes  the JWT, in its encoded (compact serialization) form
        1 byte   Cloud Connector location id length (0 if unused)
        Y bytes  the location id, base64-encoded (omitted when the length is 0)

    ``jwt`` is sent as UTF-8 bytes (a JWT is ASCII, so this matches the sample's
    ``getBytes()``). ``scc_location_id`` is base64-encoded here, exactly as the
    sample does before transmission; pass the raw location id, not a pre-encoded
    value. An empty location id emits a single 0x00 length byte and nothing else.

    Security (D-41): ``jwt`` is consumed only to produce these bytes. It never
    enters a log or an exception.
    """
    jwt_bytes = jwt.encode("utf-8")
    loc_b64 = base64.b64encode(scc_location_id.encode("utf-8")) if scc_location_id else b""
    if len(loc_b64) > 255:
        # The length prefix is a single byte; a location id this long is a caller
        # error, not a wire condition.
        raise ValueError("base64 Cloud Connector location id exceeds 255 bytes")
    return b"".join(
        (
            bytes((_JWT_SUBNEG_VERSION,)),
            struct.pack(">I", len(jwt_bytes)),
            jwt_bytes,
            bytes((len(loc_b64),)),
            loc_b64,
        )
    )


def parse_jwt_auth_reply(data: bytes) -> None:
    """Validate the SAP JWT auth reply: VER (0x01), STATUS (0x00 = success).

    Source SAP-docs cd15837 (``assertAuthenticationResponse``). Raises
    :class:`ProxyError` on a wrong version or a non-success status — never with
    the token in the message (D-41).
    """
    if len(data) != 2:
        raise ProxyError(f"SOCKS5 JWT auth reply must be 2 bytes, got {len(data)}")
    version, status = data[0], data[1]
    if version != _JWT_SUBNEG_VERSION:
        raise ProxyError(f"SOCKS5 JWT auth version mismatch: expected 0x01, got {version:#04x}")
    if status != _AUTH_SUCCESS:
        # The proxy does not say why; the token is never echoed back here.
        raise ProxyError(f"SOCKS5 proxy rejected the JWT authentication (status {status:#04x})")


# --------------------------------------------------------------------------- #
# Sans-I/O: CONNECT request / reply (RFC 1928 §4, §6)                          #
# --------------------------------------------------------------------------- #
def _address_type(host: str) -> tuple[int, bytes]:
    """Classify ``host`` as an IPv4 literal, an IPv6 literal, or a domain name.

    A dotted-quad or colon-grouped literal is sent as its packed address so the
    proxy does not re-resolve it; anything else is sent as a domain name so the
    name is resolved on the *proxy* side. The latter is what a Cloud Connector
    virtual host requires — the vhost is only resolvable behind the proxy.
    """
    try:
        return ATYP_IPV4, socket.inet_pton(socket.AF_INET, host)
    except OSError:
        pass
    try:
        return ATYP_IPV6, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    name = host.encode("ascii") if host.isascii() else host.encode("idna")
    if len(name) > 255:
        raise ValueError("SOCKS5 domain name exceeds 255 bytes")
    return ATYP_DOMAIN, bytes((len(name),)) + name


def build_connect(host: str, port: int) -> bytes:
    """Build a SOCKS5 CONNECT request (RFC 1928 §4): VER, CMD, RSV, ATYP, ADDR, PORT.

    The port is a uint16 big-endian. ``host`` is sent as a packed IP literal when
    it is one, otherwise as a domain name for proxy-side resolution.
    """
    if not 0 < port <= 0xFFFF:
        raise ValueError(f"port out of range: {port}")
    atyp, addr = _address_type(host)
    return bytes((SOCKS_VERSION, CMD_CONNECT, _RSV, atyp)) + addr + struct.pack(">H", port)


def _bound_address_len(atyp: int, tail: bytes) -> int:
    """Return the BND.ADDR+BND.PORT byte count for ``atyp`` (RFC 1928 §6).

    ``tail`` is whatever reply bytes have been read past the 4-byte header; for a
    domain-name reply its first byte is the name length, so at least one tail byte
    must already be in hand.
    """
    if atyp == ATYP_IPV4:
        return 4 + 2
    if atyp == ATYP_IPV6:
        return 16 + 2
    if atyp == ATYP_DOMAIN:
        if not tail:
            raise ProxyError("SOCKS5 CONNECT reply truncated before domain length")
        return 1 + tail[0] + 2
    raise ProxyError(f"SOCKS5 CONNECT reply has unknown address type {atyp:#04x}")


def parse_connect_reply(data: bytes) -> tuple[int, int]:
    """Parse a complete SOCKS5 CONNECT reply (RFC 1928 §6).

    Returns ``(rep, bound_port)``. Raises :class:`ProxyError` with the decoded
    meaning on any non-zero ``REP``, and on a version/length/address-type error.

    The reply is VER, REP, RSV, ATYP, BND.ADDR, BND.PORT. The bound address is of
    no use to a CONNECT client, so only its length is consumed; the bound port is
    returned for completeness and to prove the frame parsed to its end.
    """
    if len(data) < 4:
        raise ProxyError(f"SOCKS5 CONNECT reply too short: {len(data)} bytes")
    version, rep, _rsv, atyp = data[0], data[1], data[2], data[3]
    if version != SOCKS_VERSION:
        raise ProxyError(f"SOCKS5 version mismatch in CONNECT reply: {version:#04x}")
    if rep != 0x00:
        meaning = _REP_MEANING.get(rep, "unknown error")
        raise ProxyError(f"SOCKS5 CONNECT failed: {meaning} (REP {rep:#04x})")
    tail = data[4:]
    addr_len = _bound_address_len(atyp, tail)
    if len(tail) < addr_len:
        raise ProxyError("SOCKS5 CONNECT reply truncated in bound address")
    (bound_port,) = struct.unpack_from(">H", tail, addr_len - 2)
    return rep, bound_port


# --------------------------------------------------------------------------- #
# Thin I/O: synchronous handshake                                             #
# --------------------------------------------------------------------------- #
def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes, looping over TCP short reads; EOFError on close."""
    if n > _MAX_REPLY_FIELD:  # defensive: our own reads are always small
        raise ProxyError(f"SOCKS5 reply field {n} exceeds cap {_MAX_REPLY_FIELD}")
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        chunk = sock.recv_into(view[got:], n - got)
        if chunk == 0:
            raise ProxyError(f"SOCKS5 proxy closed the connection after {got}/{n} bytes")
        got += chunk
    return bytes(buf)


def _recv_connect_reply_sync(sock: socket.socket) -> tuple[int, int]:
    """Read and validate a CONNECT reply, reading exactly as many bytes as its ATYP needs."""
    head = _recv_exactly(sock, 4)
    atyp = head[3]
    if atyp == ATYP_DOMAIN:
        name_len = _recv_exactly(sock, 1)
        rest = _recv_exactly(sock, name_len[0] + 2)
        return parse_connect_reply(head + name_len + rest)
    rest = _recv_exactly(sock, _bound_address_len(atyp, b"\x00"))
    return parse_connect_reply(head + rest)


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    *,
    jwt: str | None = None,
    scc_location_id: str = "",
    connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float | None = DEFAULT_READ_TIMEOUT,
) -> socket.socket:
    """Open a TCP socket to ``dest_host:dest_port`` through a SOCKS5 proxy.

    When ``jwt`` is ``None`` the no-authentication method (0x00) is offered — the
    trusted-mode Connectivity Proxy path. When ``jwt`` is given the SAP custom
    method (0x80) is used, followed by the JWT sub-negotiation (optionally with a
    Cloud Connector ``scc_location_id``).

    Returns the connected, authenticated socket with the tunnel to the target
    already open; the caller wraps it in a :class:`~saprfclib.transport.Transport`.
    On any failure the socket is closed before the exception propagates.

    Security (D-41): ``jwt`` is never logged or placed into an exception message.
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=connect_timeout)
    try:
        sock.settimeout(read_timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        enable_keepalive(sock)

        method = AUTH_SAP_JWT if jwt is not None else AUTH_NONE
        sock.sendall(build_greeting([method]))
        selected = parse_method_selection(_recv_exactly(sock, 2))
        if selected != method:
            raise ProxyError(
                f"SOCKS5 proxy selected method {selected:#04x}, not the offered {method:#04x}"
            )

        if jwt is not None:
            sock.sendall(build_jwt_auth(jwt, scc_location_id))
            parse_jwt_auth_reply(_recv_exactly(sock, 2))

        sock.sendall(build_connect(dest_host, dest_port))
        _recv_connect_reply_sync(sock)
        return sock
    except BaseException:
        sock.close()
        raise


# --------------------------------------------------------------------------- #
# Thin I/O: asynchronous handshake                                            #
# --------------------------------------------------------------------------- #
async def _recv_connect_reply_async(reader: asyncio.StreamReader) -> tuple[int, int]:
    head = await reader.readexactly(4)
    atyp = head[3]
    if atyp == ATYP_DOMAIN:
        name_len = await reader.readexactly(1)
        rest = await reader.readexactly(name_len[0] + 2)
        return parse_connect_reply(head + name_len + rest)
    rest = await reader.readexactly(_bound_address_len(atyp, b"\x00"))
    return parse_connect_reply(head + rest)


async def socks5_connect_async(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    *,
    jwt: str | None = None,
    scc_location_id: str = "",
    connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Async counterpart of :func:`socks5_connect`.

    Returns the ``(reader, writer)`` of the tunnelled stream, ready to wrap in an
    :class:`~saprfclib.transport.AsyncTransport`. On failure the writer is closed.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port), timeout=connect_timeout
    )
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            enable_keepalive(sock)

        method = AUTH_SAP_JWT if jwt is not None else AUTH_NONE
        writer.write(build_greeting([method]))
        await writer.drain()
        selected = parse_method_selection(await reader.readexactly(2))
        if selected != method:
            raise ProxyError(
                f"SOCKS5 proxy selected method {selected:#04x}, not the offered {method:#04x}"
            )

        if jwt is not None:
            writer.write(build_jwt_auth(jwt, scc_location_id))
            await writer.drain()
            parse_jwt_auth_reply(await reader.readexactly(2))

        writer.write(build_connect(dest_host, dest_port))
        await writer.drain()
        await _recv_connect_reply_async(reader)
        return reader, writer
    except BaseException:
        writer.close()
        raise


# --------------------------------------------------------------------------- #
# OAuth2 client_credentials token fetch (D-41)                                #
# --------------------------------------------------------------------------- #
def fetch_connectivity_token(
    token_url: str,
    client_id: str,
    client_secret: str,
    *,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
) -> str:
    """Fetch a JWT access token for the SAP JWT (0x80) SOCKS5 method.

    Performs an OAuth2 ``client_credentials`` grant against ``token_url`` (the
    ``url`` of the connectivity service binding's ``uaa`` section, with
    ``/oauth/token`` appended) using HTTP Basic authentication with ``client_id``
    and ``client_secret``. Returns the ``access_token`` string.

    Pure stdlib (``urllib`` over TLS via the default verifying context) — no new
    dependency. Raises :class:`ProxyError` on an HTTP error or a response without
    an access token.

    Security (D-41): ``client_secret`` goes only into the Authorization header; it
    is never logged, and an HTTP failure reports the status code only, never the
    body (which may echo the request) or the secret.
    """
    if not token_url.lower().startswith("https://"):
        # The client_secret travels in the Authorization header; refuse to send it
        # over a cleartext channel. The connectivity binding's uaa url is https.
        raise ProxyError(
            "OAuth2 token_url must be an https:// URL (refusing to send the secret in cleartext)"
        )
    body = b"grant_type=client_credentials"
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
    request = urllib.request.Request(
        token_url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - https URL from caller's binding
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ProxyError(
            f"OAuth2 token request to the connectivity service failed (HTTP {exc.code})"
        ) from None
    except urllib.error.URLError as exc:
        # exc.reason carries no credential material (connection-level reason).
        raise ProxyError(
            f"OAuth2 token request could not reach the token endpoint: {exc.reason}"
        ) from None
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise ProxyError("OAuth2 token response did not contain an access_token")
    return token
