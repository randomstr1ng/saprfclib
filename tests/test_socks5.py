# tests/test_socks5.py
#
# Offline unit + loopback tests for SOCKS5 proxy support (issue #51, D-39/40/41).
#
# Two layers:
#   1. Pure sans-I/O builders/parsers — exact byte layout against the SAP doc
#      (using-the-tcp-protocol-for-cloud-applications-cd15837.md) and RFC 1928,
#      plus Hypothesis round-trips.
#   2. A real loopback SOCKS5 server implementing the SAP handshake (method 0x00
#      no-auth and the 0x80 JWT sub-negotiation) to drive socks5_connect and
#      socks5_connect_async end to end. No SAP system, no network beyond 127.0.0.1.
#
# Security invariants under test (T-07-PROXY-CRED / D-41): the JWT and the OAuth
# client_secret never appear in a raised ProxyError.

from __future__ import annotations

import asyncio
import json
import socket
import struct
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib import socks5
from saprfclib.exceptions import ProxyError

# --------------------------------------------------------------------------- #
# 1. Pure builders / parsers                                                  #
# --------------------------------------------------------------------------- #


def test_build_greeting_no_auth() -> None:
    assert socks5.build_greeting([socks5.AUTH_NONE]) == b"\x05\x01\x00"


def test_build_greeting_jwt() -> None:
    assert socks5.build_greeting([socks5.AUTH_SAP_JWT]) == b"\x05\x01\x80"


def test_build_greeting_rejects_empty_and_oversized() -> None:
    with pytest.raises(ValueError):
        socks5.build_greeting([])
    with pytest.raises(ValueError):
        socks5.build_greeting(list(range(256)))


def test_parse_method_selection_ok() -> None:
    assert socks5.parse_method_selection(b"\x05\x80") == socks5.AUTH_SAP_JWT
    assert socks5.parse_method_selection(b"\x05\x00") == socks5.AUTH_NONE


def test_parse_method_selection_no_acceptable() -> None:
    with pytest.raises(ProxyError, match="rejected every offered"):
        socks5.parse_method_selection(b"\x05\xff")


def test_parse_method_selection_bad_version() -> None:
    with pytest.raises(ProxyError, match="version mismatch"):
        socks5.parse_method_selection(b"\x04\x00")


def test_build_jwt_auth_layout_matches_sap_doc() -> None:
    # SAP-docs cd15837: [ver=1][jwt_len u32 BE][jwt][loc_len u8][loc b64].
    frame = socks5.build_jwt_auth("abc", "")
    assert frame == b"\x01" + struct.pack(">I", 3) + b"abc" + b"\x00"


def test_build_jwt_auth_with_location_id_base64() -> None:
    frame = socks5.build_jwt_auth("tok", "loc1")
    import base64 as _b64

    loc = _b64.b64encode(b"loc1")
    assert frame == b"\x01" + struct.pack(">I", 3) + b"tok" + bytes((len(loc),)) + loc


def test_parse_jwt_auth_reply_success_and_failure() -> None:
    socks5.parse_jwt_auth_reply(b"\x01\x00")  # no raise
    with pytest.raises(ProxyError, match="rejected the JWT"):
        socks5.parse_jwt_auth_reply(b"\x01\x01")
    with pytest.raises(ProxyError, match="version mismatch"):
        socks5.parse_jwt_auth_reply(b"\x02\x00")


def test_build_connect_domain_name() -> None:
    frame = socks5.build_connect("s4-2025", 3300)
    assert frame == b"\x05\x01\x00\x03" + bytes((7,)) + b"s4-2025" + struct.pack(">H", 3300)


def test_build_connect_ipv4_literal() -> None:
    frame = socks5.build_connect("10.0.0.5", 3301)
    assert frame == b"\x05\x01\x00\x01" + socket.inet_aton("10.0.0.5") + struct.pack(">H", 3301)


def test_build_connect_ipv6_literal() -> None:
    frame = socks5.build_connect("::1", 3302)
    assert frame[:4] == b"\x05\x01\x00\x04"
    assert frame[4:20] == socket.inet_pton(socket.AF_INET6, "::1")


def test_build_connect_rejects_bad_port() -> None:
    with pytest.raises(ValueError):
        socks5.build_connect("host", 0)
    with pytest.raises(ValueError):
        socks5.build_connect("host", 70000)


def test_parse_connect_reply_success_ipv4() -> None:
    reply = b"\x05\x00\x00\x01" + bytes(4) + struct.pack(">H", 0)
    rep, port = socks5.parse_connect_reply(reply)
    assert rep == 0 and port == 0


def test_parse_connect_reply_success_domain() -> None:
    reply = b"\x05\x00\x00\x03" + bytes((4,)) + b"host" + struct.pack(">H", 42)
    rep, port = socks5.parse_connect_reply(reply)
    assert rep == 0 and port == 42


@pytest.mark.parametrize(
    ("code", "needle"),
    [
        (0x02, "forbidden"),
        (0x03, "network unreachable"),
        (0x04, "host unreachable"),
        (0x05, "connection refused"),
        (0x07, "command not supported"),
    ],
)
def test_parse_connect_reply_error_codes(code: int, needle: str) -> None:
    reply = bytes((0x05, code, 0x00, 0x01)) + bytes(6)
    with pytest.raises(ProxyError, match=needle):
        socks5.parse_connect_reply(reply)


def test_parse_connect_reply_truncated() -> None:
    with pytest.raises(ProxyError, match="too short"):
        socks5.parse_connect_reply(b"\x05\x00")


@given(st.text(min_size=1, max_size=400), st.text(max_size=100))
def test_jwt_auth_frame_roundtrips(jwt: str, loc: str) -> None:
    import base64 as _b64

    frame = socks5.build_jwt_auth(jwt, loc)
    assert frame[0] == 0x01
    (jlen,) = struct.unpack_from(">I", frame, 1)
    assert jlen == len(jwt.encode("utf-8"))
    body = frame[5:]
    assert body[:jlen] == jwt.encode("utf-8")
    loc_len = body[jlen]
    expected_loc = _b64.b64encode(loc.encode("utf-8")) if loc else b""
    assert loc_len == len(expected_loc)
    assert body[jlen + 1 : jlen + 1 + loc_len] == expected_loc


@given(st.integers(min_value=1, max_value=0xFFFF))
def test_connect_port_roundtrips(port: int) -> None:
    frame = socks5.build_connect("example.test", port)
    (parsed,) = struct.unpack(">H", frame[-2:])
    assert parsed == port


# --------------------------------------------------------------------------- #
# 2. Loopback SOCKS5 server implementing the SAP handshake                     #
# --------------------------------------------------------------------------- #


def _recv_exactly(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf.extend(chunk)
    return bytes(buf)


class FakeSapSocks5Server:
    """A 127.0.0.1 SOCKS5 server speaking the SAP handshake, for one connection.

    Configurable to fail at each stage. Records the method offered, the JWT and
    location id received, and the CONNECT target, for assertions.
    """

    def __init__(
        self,
        *,
        method_reply: int | None = None,
        auth_status: int = 0x00,
        connect_rep: int = 0x00,
    ) -> None:
        self._method_reply = method_reply  # None → echo the client's method
        self._auth_status = auth_status
        self._connect_rep = connect_rep
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.host, self.port = self._sock.getsockname()
        self.offered_methods: list[int] = []
        self.jwt: bytes | None = None
        self.location_id: bytes | None = None
        self.dest_host: str | None = None
        self.dest_port: int | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            try:
                self._handshake(conn)
            except (OSError, EOFError):
                pass

    def _handshake(self, conn: socket.socket) -> None:
        ver, nmethods = _recv_exactly(conn, 2)
        assert ver == 0x05
        methods = _recv_exactly(conn, nmethods)
        self.offered_methods = list(methods)
        chosen = self._method_reply if self._method_reply is not None else methods[0]
        conn.sendall(bytes((0x05, chosen)))
        if chosen == socks5.AUTH_NO_ACCEPTABLE:
            return
        if chosen == socks5.AUTH_SAP_JWT:
            subver = _recv_exactly(conn, 1)[0]
            assert subver == 0x01
            (jlen,) = struct.unpack(">I", _recv_exactly(conn, 4))
            self.jwt = _recv_exactly(conn, jlen)
            loc_len = _recv_exactly(conn, 1)[0]
            self.location_id = _recv_exactly(conn, loc_len) if loc_len else b""
            conn.sendall(bytes((0x01, self._auth_status)))
            if self._auth_status != 0x00:
                return
        # CONNECT request
        head = _recv_exactly(conn, 4)
        assert head[0] == 0x05 and head[1] == 0x01
        atyp = head[3]
        if atyp == socks5.ATYP_DOMAIN:
            dlen = _recv_exactly(conn, 1)[0]
            self.dest_host = _recv_exactly(conn, dlen).decode()
        elif atyp == socks5.ATYP_IPV4:
            self.dest_host = socket.inet_ntoa(_recv_exactly(conn, 4))
        else:
            self.dest_host = socket.inet_ntop(socket.AF_INET6, _recv_exactly(conn, 16))
        (self.dest_port,) = struct.unpack(">H", _recv_exactly(conn, 2))
        conn.sendall(bytes((0x05, self._connect_rep, 0x00, 0x01)) + bytes(4) + struct.pack(">H", 0))
        if self._connect_rep == 0x00:
            # Prove the tunnel is open end to end.
            conn.sendall(b"OK")

    def close(self) -> None:
        self._sock.close()


@pytest.fixture
def no_auth_server() -> Iterator[FakeSapSocks5Server]:
    server = FakeSapSocks5Server()
    yield server
    server.close()


def test_socks5_connect_no_auth_opens_tunnel(no_auth_server: FakeSapSocks5Server) -> None:
    sock = socks5.socks5_connect(
        no_auth_server.host, no_auth_server.port, "s4-2025", 3300, connect_timeout=5
    )
    try:
        assert sock.recv(2) == b"OK"
    finally:
        sock.close()
    assert no_auth_server.offered_methods == [socks5.AUTH_NONE]
    assert no_auth_server.dest_host == "s4-2025"
    assert no_auth_server.dest_port == 3300


def test_socks5_connect_jwt_sends_token_and_location() -> None:
    server = FakeSapSocks5Server()
    try:
        sock = socks5.socks5_connect(
            server.host,
            server.port,
            "vhost.internal",
            3300,
            jwt="my.jwt.token",
            scc_location_id="LOC1",
            connect_timeout=5,
        )
        try:
            assert sock.recv(2) == b"OK"
        finally:
            sock.close()
        assert server.offered_methods == [socks5.AUTH_SAP_JWT]
        assert server.jwt == b"my.jwt.token"
        import base64 as _b64

        assert server.location_id == _b64.b64encode(b"LOC1")
    finally:
        server.close()


def test_socks5_connect_auth_failure_raises_no_token_leak() -> None:
    server = FakeSapSocks5Server(auth_status=0x01)
    try:
        with pytest.raises(ProxyError) as exc:
            socks5.socks5_connect(
                server.host, server.port, "h", 3300, jwt="SECRET-TOKEN", connect_timeout=5
            )
        assert "SECRET-TOKEN" not in str(exc.value)
    finally:
        server.close()


def test_socks5_connect_rejects_method_mismatch() -> None:
    # Client offers no-auth; server insists on 0x80.
    server = FakeSapSocks5Server(method_reply=socks5.AUTH_SAP_JWT)
    try:
        with pytest.raises(ProxyError, match="selected method"):
            socks5.socks5_connect(server.host, server.port, "h", 3300, connect_timeout=5)
    finally:
        server.close()


def test_socks5_connect_connect_failure_raises() -> None:
    server = FakeSapSocks5Server(connect_rep=0x05)  # connection refused
    try:
        with pytest.raises(ProxyError, match="connection refused"):
            socks5.socks5_connect(server.host, server.port, "h", 3300, connect_timeout=5)
    finally:
        server.close()


def test_socks5_connect_async_no_auth(no_auth_server: FakeSapSocks5Server) -> None:
    async def run() -> bytes:
        reader, writer = await socks5.socks5_connect_async(
            no_auth_server.host, no_auth_server.port, "s4-2025", 3300, connect_timeout=5
        )
        data = await reader.readexactly(2)
        writer.close()
        await writer.wait_closed()
        return data

    assert asyncio.run(run()) == b"OK"
    assert no_auth_server.dest_host == "s4-2025"


def test_socks5_connect_async_jwt() -> None:
    server = FakeSapSocks5Server()

    async def run() -> bytes:
        reader, writer = await socks5.socks5_connect_async(
            server.host,
            server.port,
            "vhost",
            3300,
            jwt="tok",
            scc_location_id="L",
            connect_timeout=5,
        )
        data = await reader.readexactly(2)
        writer.close()
        await writer.wait_closed()
        return data

    try:
        assert asyncio.run(run()) == b"OK"
        assert server.jwt == b"tok"
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# 3. OAuth2 client_credentials token fetch                                     #
# --------------------------------------------------------------------------- #


def test_fetch_token_rejects_http_url() -> None:
    with pytest.raises(ProxyError, match="https"):
        socks5.fetch_connectivity_token("http://insecure/oauth/token", "id", "secret")


class _TokenHandler(BaseHTTPRequestHandler):
    access_token = "fetched.jwt.value"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"access_token": self.access_token}).encode())

    def log_message(self, *args: object) -> None:  # silence test server
        pass


def test_fetch_token_https_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    # Serve plain HTTP but let the https:// guard pass, so the OAuth flow itself is
    # exercised without standing up TLS in the test.
    server = HTTPServer(("127.0.0.1", 0), _TokenHandler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    host, port = server.server_address
    real_url = f"http://{host}:{port}/oauth/token"

    import saprfclib.socks5 as mod

    orig = mod.urllib.request.urlopen

    def fake_urlopen(req: object, *a: object, **k: object) -> object:
        # Rewrite the https URL the code built back to our http test server.
        req.full_url = real_url  # type: ignore[attr-defined]
        return orig(req, *a, **k)

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    token = socks5.fetch_connectivity_token("https://uaa.example/oauth/token", "client", "s3cr3t")
    assert token == "fetched.jwt.value"


# --------------------------------------------------------------------------- #
# 4. Connectivity service binding → connect() kwargs                           #
# --------------------------------------------------------------------------- #

_CREDS = {
    "onpremise_proxy_host": "connectivity-proxy.internal",
    "onpremise_socks5_proxy_port": "20004",
    "onpremise_proxy_http_port": "20003",
    "clientid": "cid",
    "clientsecret": "csecret",
    "token_service_url": "https://sub.authentication.eu10.hana.ondemand.com",
}


def test_connectivity_kwargs_from_raw_credentials() -> None:
    cfg = socks5.connectivity_proxy_kwargs(_CREDS)
    assert cfg["proxy_type"] == "socks5"
    assert cfg["proxy_host"] == "connectivity-proxy.internal"
    assert cfg["proxy_port"] == 20004
    assert cfg["proxy_client_id"] == "cid"
    assert cfg["proxy_client_secret"] == "csecret"
    assert cfg["proxy_token_url"] == (
        "https://sub.authentication.eu10.hana.ondemand.com/oauth/token"
    )


def test_connectivity_kwargs_trusted_mode_omits_auth() -> None:
    cfg = socks5.connectivity_proxy_kwargs(_CREDS, with_auth=False)
    assert cfg == {
        "proxy_type": "socks5",
        "proxy_host": "connectivity-proxy.internal",
        "proxy_port": 20004,
    }


def test_connectivity_kwargs_deprecated_url_key() -> None:
    creds = {k: v for k, v in _CREDS.items() if k != "token_service_url"}
    creds["url"] = "https://sub.authentication.eu10.hana.ondemand.com/"
    cfg = socks5.connectivity_proxy_kwargs(creds)
    assert cfg["proxy_token_url"].endswith("/oauth/token")
    assert "//oauth" not in cfg["proxy_token_url"].replace("https://", "")


def test_connectivity_kwargs_from_vcap_shape() -> None:
    vcap = {"connectivity": [{"credentials": _CREDS}]}
    cfg = socks5.connectivity_proxy_kwargs(vcap)
    assert cfg["proxy_host"] == "connectivity-proxy.internal"


def test_connectivity_kwargs_from_instance_shape() -> None:
    cfg = socks5.connectivity_proxy_kwargs({"credentials": _CREDS})
    assert cfg["proxy_port"] == 20004


def test_connectivity_kwargs_from_json_string() -> None:
    cfg = socks5.connectivity_proxy_kwargs(json.dumps({"connectivity": [{"credentials": _CREDS}]}))
    assert cfg["proxy_host"] == "connectivity-proxy.internal"


def test_connectivity_kwargs_missing_auth_raises() -> None:
    creds = {
        "onpremise_proxy_host": "h",
        "onpremise_socks5_proxy_port": "20004",
    }
    with pytest.raises(ProxyError, match="clientid/clientsecret"):
        socks5.connectivity_proxy_kwargs(creds)
    # ... but trusted mode is fine without credentials.
    assert socks5.connectivity_proxy_kwargs(creds, with_auth=False)["proxy_port"] == 20004


def test_connectivity_kwargs_missing_host_raises() -> None:
    # Recognised as a credentials mapping (has the SOCKS5 port key) but no host.
    with pytest.raises(ProxyError, match="onpremise_proxy_host"):
        socks5.connectivity_proxy_kwargs({"onpremise_socks5_proxy_port": "20004"}, with_auth=False)


def test_connectivity_kwargs_unrecognised_binding_raises() -> None:
    with pytest.raises(ProxyError, match="could not find connectivity credentials"):
        socks5.connectivity_proxy_kwargs({"clientid": "x"}, with_auth=False)


def test_connectivity_kwargs_reads_vcap_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VCAP_SERVICES", json.dumps({"connectivity": [{"credentials": _CREDS}]}))
    monkeypatch.delenv("SERVICE_BINDING_ROOT", raising=False)
    cfg = socks5.connectivity_proxy_kwargs()
    assert cfg["proxy_host"] == "connectivity-proxy.internal"


def test_connectivity_kwargs_no_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VCAP_SERVICES", raising=False)
    monkeypatch.delenv("SERVICE_BINDING_ROOT", raising=False)
    with pytest.raises(ProxyError, match="neither VCAP_SERVICES nor SERVICE_BINDING_ROOT"):
        socks5.connectivity_proxy_kwargs()


def test_connectivity_kwargs_service_binding_root_file_per_key(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pathlib

    root = pathlib.Path(str(tmp_path))
    binding = root / "my-connectivity"
    binding.mkdir()
    (binding / "type").write_text("connectivity")
    for key, value in _CREDS.items():
        (binding / key).write_text(value)
    monkeypatch.delenv("VCAP_SERVICES", raising=False)
    monkeypatch.setenv("SERVICE_BINDING_ROOT", str(root))
    cfg = socks5.connectivity_proxy_kwargs()
    assert cfg["proxy_port"] == 20004
    assert cfg["proxy_client_secret"] == "csecret"


def test_connectivity_kwargs_service_binding_root_credentials_json(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pathlib

    root = pathlib.Path(str(tmp_path))
    binding = root / "conn"
    binding.mkdir()
    (binding / "type").write_text("connectivity")
    (binding / "credentials").write_text(json.dumps(_CREDS))
    monkeypatch.delenv("VCAP_SERVICES", raising=False)
    monkeypatch.setenv("SERVICE_BINDING_ROOT", str(root))
    cfg = socks5.connectivity_proxy_kwargs(with_auth=False)
    assert cfg["proxy_host"] == "connectivity-proxy.internal"


def test_connectivity_kwargs_secret_not_in_error() -> None:
    # A binding that will fail auth resolution must not echo any secret it did hold.
    creds = {"onpremise_proxy_host": "h", "onpremise_socks5_proxy_port": "20004", "clientid": "x"}
    with pytest.raises(ProxyError) as exc:
        socks5.connectivity_proxy_kwargs(creds)
    assert "x" == creds["clientid"]  # sanity
    # clientsecret absent here; ensure the message is about the missing field only.
    assert "clientsecret" in str(exc.value)
