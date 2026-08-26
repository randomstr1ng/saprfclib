# tests/test_connection.py
#
# Offline tests for the sync Connection facade (Plan 03-03, TRANS-04/05/06).
# Every test drives the facade through a MockTransport scripted with the same
# golden NI/GW handshake fixtures used by test_session.py plus a synthetic
# logon-response TLV stream — ZERO sockets, no live network.
#
# The facade binds a Transport + Session, walks the handshake to READY, and
# exposes connect()/ping()/close()/get_connection_attributes() with a single
# in-flight lock (CPIC single-conversation, TRANS-04).

import struct

import pytest

from saprfclib.connection import (
    Connection,
    _ab_scramble,
    _scramble_password,
)
from saprfclib.session import ConnectionAttributes, SessionState
from tests._mocks import MockTransport
from tests.conftest import GOLDEN_ROOT, load_fixture

HANDSHAKE_DIR = GOLDEN_ROOT / "handshake"


# --------------------------------------------------------------------------- #
# Synthetic TLV helpers (mirror test_session.py — [ASSUMED] frame-15 shape).
# --------------------------------------------------------------------------- #
def _tlv(tag: int, value: bytes) -> bytes:
    return struct.pack(">HH", tag, len(value)) + value


def _logon_response(rc: int = 0) -> bytes:
    """Synthetic server logon-response TLV payload (frame 15), rc=0 ⇒ READY.

    RE truth: error is signaled by tag 0x0402 (error message text, absent on
    success).  Tag 0x0420 is NOT present in live logon-response captures.
    """
    parts: list[bytes] = [
        _tlv(0x0450, b"A4H"),
        _tlv(0x0452, b"00"),
        _tlv(0x0453, b"vhcala4hci"),
        _tlv(0x0012, b"758"),
        _tlv(0x0013, b"793"),
        _tlv(0x0150, b"DEVELOPER"),
        _tlv(0x0151, b"001"),
        _tlv(0x0152, b"E"),
    ]
    if rc != 0:
        parts.append(_tlv(0x0402, f"logon error rc={rc}".encode()))
    parts.append(_tlv(0xFFFF, b""))
    return b"".join(parts)


def _rfcping_ok() -> bytes:
    """Synthetic RFCPING-OK response: a TLV stream with return-code 0x0420 == 0."""
    return b"".join(
        [
            _tlv(0x0420, struct.pack(">I", 0)),
            _tlv(0xFFFF, b""),
        ]
    )


def _handshake_responses() -> list[bytes]:
    """The four scripted server frames that drive a Connection to READY."""
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response")
    gw_conn = load_fixture(HANDSHAKE_DIR, "gw_connect_response")
    gw_done = load_fixture(HANDSHAKE_DIR, "gw_done_server")
    return [
        ni_resp.payload_bytes,
        gw_conn.payload_bytes,
        gw_done.payload_bytes,
        _logon_response(rc=0),
    ]


def _ready_connection(extra: list[bytes] | None = None) -> tuple[Connection, MockTransport]:
    """Build a Connection driven to READY over a MockTransport.

    ``extra`` appends further scripted responses (e.g. an RFCPING-OK) consumed
    after the handshake.
    """
    responses = _handshake_responses() + (extra or [])
    transport = MockTransport(responses)
    conn = Connection(transport)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    return conn, transport


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_connect_drives_handshake_to_ready() -> None:
    """A Connection bound to a scripted MockTransport reaches READY and exposes
    ConnectionAttributes via get_connection_attributes()."""
    conn, _ = _ready_connection()
    assert conn._session.state is SessionState.READY
    attrs = conn.get_connection_attributes()
    assert isinstance(attrs, ConnectionAttributes)
    assert attrs.codepage == "4103"
    assert attrs.sys_id == "A4H"


def test_get_attributes_before_ready_raises() -> None:
    """get_connection_attributes() on a fresh (non-READY) Connection raises
    ValueError mentioning READY."""
    conn = Connection(MockTransport([]))
    with pytest.raises(ValueError, match="READY"):
        conn.get_connection_attributes()


def test_ping_on_ready_returns_true() -> None:
    """ping() on a READY connection (scripted RFCPING-OK) returns True and leaves
    the state READY."""
    conn, _ = _ready_connection(extra=[_rfcping_ok()])
    assert conn.ping() is True
    assert conn._session.state is SessionState.READY


def test_ping_rejected_when_not_ready() -> None:
    """ping() before READY raises ValueError (state guard)."""
    conn = Connection(MockTransport([]))
    with pytest.raises(ValueError):
        conn.ping()


def test_single_in_flight_guard() -> None:
    """Starting a second call while one is marked IN_CALL raises ValueError
    (CPIC single-conversation, TRANS-04)."""
    conn, _ = _ready_connection()
    # Simulate a call already in flight.
    conn._session.mark_in_call()
    assert conn._session.state is SessionState.IN_CALL
    with pytest.raises(ValueError):
        conn.ping()


def test_close_is_idempotent_and_safe() -> None:
    """close() on a fresh, a READY, and an already-closed Connection never raises;
    transport.close() is invoked and state becomes CLOSED."""
    # Fresh.
    fresh_t = MockTransport([])
    fresh = Connection(fresh_t)
    fresh.close()
    assert fresh_t.closed is True
    assert fresh._session.state is SessionState.CLOSED
    fresh.close()  # idempotent — no raise

    # READY.
    conn, transport = _ready_connection()
    conn.close()
    assert transport.closed is True
    assert conn._session.state is SessionState.CLOSED


# --------------------------------------------------------------------------- #
# 0x0117 password scramble (Plan 04-01 Task 2; RE: docs/protocol/handshake.md)
# --------------------------------------------------------------------------- #
def _parse_tlv_stream(frame: bytes) -> dict[int, bytes]:
    """Parse TLV stream (simple or extended format with repeated-tag suffix)."""
    out: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(frame):
        tag, length = struct.unpack_from(">HH", frame, pos)
        pos += 4
        if tag == 0xFFFF:
            break
        out[tag] = frame[pos : pos + length]
        pos += length
        if pos + 2 <= len(frame) and struct.unpack_from(">H", frame, pos)[0] == tag:
            pos += 2
    return out


def test_ab_scramble_is_its_own_inverse() -> None:
    """the password-scramble cipher applied twice with the same seed is the identity (symmetric
    XOR stream — RE: unscramblePassword recovers plaintext with the same seed)."""
    original = bytearray(b"hunter2-passw0rd")
    work = bytearray(original)
    _ab_scramble(work, seed=0x1234ABCD)
    assert bytes(work) != bytes(original)  # actually scrambled
    _ab_scramble(work, seed=0x1234ABCD)
    assert bytes(work) == bytes(original)  # round-trips back


def test_scramble_password_layout_and_length() -> None:
    """_scramble_password emits seed(4B LE) + the password-scramble cipher(pw); a 13-char password
    yields exactly 17 bytes (matches the captured 0x0117 field length).
    Seed is stored little-endian (x86 native): bytes 96 4d 05 30 = LE 0x30054d96."""
    value = _scramble_password("DemoPassw0rd!", seed=0xDEADBEEF)  # 13 chars
    assert len(value) == 17  # 4-byte seed + 13 password bytes
    assert value[:4] == struct.pack("<I", 0xDEADBEEF)  # seed prefix (LE)


def test_scramble_password_recovers_via_inverse() -> None:
    """The scrambled body un-scrambles back to the plaintext bytes using the
    embedded seed — proving the wire format is faithful and reversible."""
    pw = "S3cr3t"
    value = _scramble_password(pw, seed=0x01020304)
    seed = int.from_bytes(value[:4], "little")  # LE on wire
    body = bytearray(value[4:])
    _ab_scramble(body, seed)
    assert bytes(body) == pw.encode("latin-1")


def test_logon_request_emits_0x0117_and_hides_plaintext() -> None:
    """_build_logon_request emits a 17-byte 0x0117 record for a 13-char password
    and the plaintext password never appears anywhere in the frame bytes."""
    pw = "DemoPassw0rd!"  # 13 chars
    frame = Connection._build_logon_request(
        client="001", user="DEVELOPER", passwd=pw, seed=0xDEADBEEF
    )
    tlv = _parse_tlv_stream(frame)
    assert 0x0117 in tlv
    assert len(tlv[0x0117]) == 17  # seed(4) + 13 scrambled bytes
    # No-plaintext-leak: the cleartext password must not appear in the frame in
    # any single-byte or UTF-16LE encoding (threat T-04-CRED).
    assert pw.encode("latin-1") not in frame
    assert pw.encode("utf-16-le") not in frame


# --------------------------------------------------------------------------- #
# Phase 4: call() implementation tests (Task 3)
# --------------------------------------------------------------------------- #


def _invoke_response_for_stfc(echo: str = "hi", resp: str = "SAP test") -> bytes:
    """Build a synthetic STFC_CONNECTION invoke response TLV stream."""
    import struct as _struct

    from saprfclib.invoke import tlv_record as _tr

    def _pad255(s: str) -> bytes:
        enc = s.encode("utf-16-le")
        return enc + b"\x20\x00" * (255 - len(s))

    return (
        _tr(0x0500, b"")
        + _tr(0x0503, b"")
        + _tr(0x0514, b"\x00" * 16)
        + _tr(0x0420, _struct.pack(">I", 0))
        + _tr(0x0512, b"")
        + _tr(0x0205, "ECHOTEXT".encode("utf-16-le"))
        + _tr(0x0205, "RESPTEXT".encode("utf-16-le"))
        + _tr(0x0201, "ECHOTEXT".encode("utf-16-le"))
        + _tr(0x0203, _pad255(echo))
        + _tr(0x0201, "RESPTEXT".encode("utf-16-le"))
        + _tr(0x0203, _pad255(resp))
        + _struct.pack(">HH", 0xFFFF, 0)
        + b"\xff\xff"
    )


def _stfc_desc():
    """FunctionDesc for STFC_CONNECTION with direction-tagged parameters."""
    from saprfclib.types import RFC_EXPORT, RFC_IMPORT, FieldDesc, FunctionDesc

    CHAR = 0

    def _char255(name, direction):
        return FieldDesc(
            name=name,
            rfctype=CHAR,
            nuc_length=255,
            nuc_offset=0,
            uc_length=510,
            uc_offset=0,
            decimals=0,
            unicode_mode=True,
            direction=direction,
        )

    return FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            _char255("ECHOTEXT", RFC_EXPORT),
            _char255("RESPTEXT", RFC_EXPORT),
            _char255("REQUTEXT", RFC_IMPORT),
        ],
    )


def _ready_connection_with_invoke(
    invoke_responses: list[bytes],
) -> tuple["Connection", "MockTransport"]:
    """Build a Connection at READY with additional scripted invoke responses.

    Pre-populates the MetadataCache so call() skips the bootstrap round-trip.
    """
    from saprfclib.metadata import MetadataCache

    all_responses = _handshake_responses() + invoke_responses
    transport = MockTransport(all_responses)
    conn = Connection(transport)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    # Pre-populate cache so call() uses the cached descriptor (no bootstrap needed)
    if not hasattr(conn, "_cache"):
        conn._cache = MetadataCache()
    conn._cache.put(conn.sys_id, _stfc_desc())
    return conn, transport


def test_call_returns_native_dict() -> None:
    """conn.call('STFC_CONNECTION', REQUTEXT='hi') returns a dict with EXPORTING
    params decoded from the scripted invoke response (CLIENT-01/03)."""
    conn, _ = _ready_connection_with_invoke([_invoke_response_for_stfc(echo="hi")])
    result = conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert isinstance(result, dict)
    assert "ECHOTEXT" in result
    assert "RESPTEXT" in result
    # Codec returns str for CHAR; strip trailing spaces
    assert result["ECHOTEXT"].strip() == "hi"


def test_call_date_time_conversion() -> None:
    """DATE-typed result '20260627' becomes datetime.date(2026, 6, 27);
    TIME-typed result '143005' becomes datetime.time(14, 30, 5);
    empty/zero values become None (D-24/CLIENT-03)."""
    import datetime
    import struct as _struct

    from saprfclib.invoke import tlv_record as _tr
    from saprfclib.types import RFC_EXPORT, RFC_IMPORT, FieldDesc, FunctionDesc

    # Build a FunctionDesc with DATE and TIME EXPORTING params
    DATE_TYPE, TIME_TYPE, CHAR_TYPE = 1, 3, 0

    def _fixed_field(name, rfctype, nuc_len, direction):
        uc_len = nuc_len * 2 if rfctype in (0, 1, 3, 6, 29) else nuc_len
        return FieldDesc(
            name=name,
            rfctype=rfctype,
            nuc_length=nuc_len,
            nuc_offset=0,
            uc_length=uc_len,
            uc_offset=0,
            decimals=0,
            unicode_mode=True,
            direction=direction,
        )

    desc = FunctionDesc(
        name="MY_FM",
        parameters=[
            _fixed_field("MYDATE", DATE_TYPE, 8, RFC_EXPORT),  # DATE(8 chars)
            _fixed_field("MYTIME", TIME_TYPE, 6, RFC_EXPORT),  # TIME(6 chars)
            _fixed_field("EMPTY_DATE", DATE_TYPE, 8, RFC_EXPORT),
            _fixed_field("DUMMY", CHAR_TYPE, 1, RFC_IMPORT),
        ],
    )

    conn, transport = _ready_connection_with_invoke([])
    conn._cache.put(conn.sys_id, desc)

    # Build the response manually
    date_val = "20260627".encode("utf-16-le")  # DATE(8) = 16 bytes
    time_val = "143005".encode("utf-16-le")  # TIME(6) = 12 bytes
    empty_date = "00000000".encode("utf-16-le")  # empty/zero DATE

    # Re-script the transport to include this response
    invoke_resp = (
        _tr(0x0500, b"")
        + _tr(0x0420, _struct.pack(">I", 0))
        + _tr(0x0512, b"")
        + _tr(0x0201, "MYDATE".encode("utf-16-le"))
        + _tr(0x0203, date_val)
        + _tr(0x0201, "MYTIME".encode("utf-16-le"))
        + _tr(0x0203, time_val)
        + _tr(0x0201, "EMPTY_DATE".encode("utf-16-le"))
        + _tr(0x0203, empty_date)
        + _struct.pack(">HH", 0xFFFF, 0)
        + b"\xff\xff"
    )
    transport._responses.append(invoke_resp)

    result = conn.call("MY_FM", DUMMY="x")
    assert result["MYDATE"] == datetime.date(2026, 6, 27), f"Got {result['MYDATE']!r}"
    assert result["MYTIME"] == datetime.time(14, 30, 5), f"Got {result['MYTIME']!r}"
    assert result["EMPTY_DATE"] is None, f"Got {result['EMPTY_DATE']!r}"


def test_call_abap_exception_raises_application_error() -> None:
    """An invoke response with an ABAP exception raises AbapApplicationError (CLIENT-04)."""
    import pathlib

    from saprfclib.exceptions import AbapApplicationError

    # Exception response from the golden fixture
    fixture = pathlib.Path(__file__).parent / "golden" / "framing" / "stfc_exception_response.bin"
    raw = fixture.read_bytes()
    exception_tlv = raw[4:][80:]  # strip NI header + GW preamble

    conn, _ = _ready_connection_with_invoke([exception_tlv])
    with pytest.raises(AbapApplicationError) as exc_info:
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert exc_info.value.key == "EXAMPLE"


def test_call_eof_raises_communication_error() -> None:
    """An EOF during the invoke round-trip raises CommunicationError with
    original_exception set (CLIENT-06)."""
    from saprfclib.exceptions import CommunicationError

    # No extra responses scripted — recv_message raises EOFError
    conn, _ = _ready_connection_with_invoke([])
    with pytest.raises(CommunicationError) as exc_info:
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert exc_info.value.original_exception is not None
    assert isinstance(exc_info.value.original_exception, EOFError)


def test_call_state_guard_not_ready_raises() -> None:
    """call() before READY raises ValueError (single-in-flight guard preserved)."""
    conn = Connection(MockTransport([]))
    with pytest.raises(ValueError):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")


def test_call_restores_ready_after_exception() -> None:
    """Session returns to READY after an exception in call() (finally guard, Task 3 Test 5)."""
    from saprfclib.exceptions import CommunicationError
    from saprfclib.session import SessionState

    # No invoke responses → EOFError → CommunicationError
    conn, _ = _ready_connection_with_invoke([])
    with pytest.raises(CommunicationError):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    # Must be READY again after the exception
    assert conn._session.state is SessionState.READY


def test_get_connection_attributes_returns_attributes() -> None:
    """get_connection_attributes() returns the negotiated ConnectionAttributes (CLIENT-07)."""
    from saprfclib.session import ConnectionAttributes

    conn, _ = _ready_connection_with_invoke([])
    attrs = conn.get_connection_attributes()
    assert isinstance(attrs, ConnectionAttributes)
    assert attrs.sys_id == "A4H"


def test_connection_has_metadata_cache() -> None:
    """Connection.__init__ creates a MetadataCache (Task 3 wiring check)."""
    from saprfclib.metadata import MetadataCache

    conn = Connection(MockTransport([]))
    assert hasattr(conn, "_cache")
    assert isinstance(conn._cache, MetadataCache)


def test_connection_has_sys_id_property() -> None:
    """conn.sys_id returns None before READY and the sys_id string after (Task 3)."""
    conn = Connection(MockTransport([]))
    assert conn.sys_id is None  # not yet READY
    conn2, _ = _ready_connection_with_invoke([])
    assert conn2.sys_id == "A4H"


# --------------------------------------------------------------------------- #
# wRFC routing (Plan 07-P05, SEC-05): connect(wshost=...) → connect_ws         #
# --------------------------------------------------------------------------- #
def test_connect_routes_to_connect_ws_with_defaults(monkeypatch) -> None:
    """connect(wshost=..., wsport=...) routes through connect_ws (D-16/D-17).

    Patches saprfclib.ws.connect_ws to return a handshake-scripted MockTransport and
    asserts: connect_ws was called with ws_path defaulting to
    "/sap/bc/rfc?sap-apc-stateful=true" and wsport 443, the plain connect_tcp
    path was NOT taken, and the returned Connection wraps the fake transport and
    reaches READY.
    """
    import saprfclib.connection as _connmod
    import saprfclib.ws as _ws
    from saprfclib import connect as _connect

    fake = MockTransport(_handshake_responses())
    calls: dict[str, object] = {}

    def _fake_connect_ws(wshost, wsport, **kwargs):
        calls["wshost"] = wshost
        calls["wsport"] = wsport
        calls.update(kwargs)
        return fake

    monkeypatch.setattr(_ws, "connect_ws", _fake_connect_ws)

    # Guard: the plain TCP path must NOT be taken when wshost is set.
    def _boom_connect_tcp(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("connect_tcp must not be called on the wRFC path")

    monkeypatch.setattr(_connmod, "connect_tcp", _boom_connect_tcp)

    conn = _connect(
        ashost="ignored",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
        wshost="bt.example",
        wsport=443,
    )

    assert conn._transport is fake
    assert conn._session.state is SessionState.READY
    assert calls["wshost"] == "bt.example"
    assert calls["wsport"] == 443
    assert calls["ws_path"] == "/sap/bc/rfc?sap-apc-stateful=true"


def test_connect_ws_flows_proxy_params_through(monkeypatch) -> None:
    """ws_proxy_host/port/user/pass flow through to connect_ws unchanged (D-20)."""
    import saprfclib.ws as _ws
    from saprfclib import connect as _connect

    fake = MockTransport(_handshake_responses())
    calls: dict[str, object] = {}

    def _fake_connect_ws(wshost, wsport, **kwargs):
        calls.update(kwargs)
        calls["wsport"] = wsport
        return fake

    monkeypatch.setattr(_ws, "connect_ws", _fake_connect_ws)

    _connect(
        ashost="ignored",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
        wshost="bt.example",
        ws_path="/custom/path",
        ws_proxy_host="proxy.corp",
        ws_proxy_port=8080,
        ws_proxy_user="pxuser",
        ws_proxy_pass="pxsecret",
    )

    assert calls["wsport"] == 443  # wsport default
    assert calls["ws_path"] == "/custom/path"
    assert calls["ws_proxy_host"] == "proxy.corp"
    assert calls["ws_proxy_port"] == 8080
    assert calls["ws_proxy_user"] == "pxuser"
    assert calls["ws_proxy_pass"] == "pxsecret"


def test_connect_ws_proxy_pass_never_in_exception(monkeypatch) -> None:
    """ws_proxy_pass (T-07-PROXY-CRED) must never leak into a raised exception."""
    import saprfclib.ws as _ws
    from saprfclib import connect as _connect

    secret = "sup3r-s3cret-proxy-pw"

    def _fake_connect_ws(wshost, wsport, **kwargs):
        raise RuntimeError("HTTP CONNECT proxy refused the tunnel (status 407)")

    monkeypatch.setattr(_ws, "connect_ws", _fake_connect_ws)

    with pytest.raises(RuntimeError) as excinfo:
        _connect(
            ashost="ignored",
            sysnr="00",
            client="001",
            user="DEVELOPER",
            passwd="secret",
            wshost="bt.example",
            ws_proxy_host="proxy.corp",
            ws_proxy_pass=secret,
        )
    assert secret not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# SNC routing (Plan 07-P03, SEC-02/03): connect(snc_lib=...) → SncTransport     #
# snc_lib presence is the switch (D-13); no separate snc_mode flag.             #
# All offline: SncTransport + connect_tcp are patched so no real .so / socket   #
# is touched. snc_lib/snc_partnername/snc_myname never appear in any exception  #
# (T-07-CRED).                                                                   #
# --------------------------------------------------------------------------- #
def test_connect_routes_to_snc_transport_with_defaults(monkeypatch) -> None:
    """connect(snc_lib=..., snc_partnername=...) wraps connect_tcp in SncTransport.

    Patches saprfclib.snc.SncTransport and saprfclib.connection.connect_tcp so no real
    lib/socket is touched, then asserts: connect_tcp built the inner transport,
    SncTransport wrapped that inner with snc_qop defaulting to 3 and snc_sso
    False (D-12), and the returned Connection wraps the SncTransport and reaches
    READY (D-13).
    """
    import saprfclib.connection as _connmod
    import saprfclib.snc as _snc
    from saprfclib import connect as _connect

    # NI exchange happens on the plain inner transport before SncTransport is
    # created — inner_sentinel must provide the NI response.  fake_snc drives
    # the remaining GW+logon legs (NI leg already consumed on inner_sentinel).
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response").payload_bytes
    inner_sentinel = MockTransport([ni_resp])
    fake_snc = MockTransport(_handshake_responses()[1:])
    calls: dict[str, object] = {}

    def _fake_connect_tcp(host, port, **kwargs):
        calls["tcp_host"] = host
        calls["tcp_port"] = port
        return inner_sentinel

    def _fake_snc_transport(inner, **kwargs):
        calls["inner"] = inner
        calls.update(kwargs)
        return fake_snc

    monkeypatch.setattr(_connmod, "connect_tcp", _fake_connect_tcp)
    monkeypatch.setattr(_snc, "SncTransport", _fake_snc_transport)

    conn = _connect(
        ashost="sap.example",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
        snc_lib="/fake.so",
        snc_partnername="p:CN=S",
    )

    assert conn._transport is fake_snc
    assert conn._session.state is SessionState.READY
    # connect_tcp built the inner transport at the secure gateway port (4800 + sysnr).
    assert calls["tcp_host"] == "sap.example"
    assert calls["tcp_port"] == 4800
    # SncTransport wrapped exactly that inner transport.
    assert calls["inner"] is inner_sentinel
    assert calls["snc_lib"] == "/fake.so"
    assert calls["snc_partnername"] == "p:CN=S"
    assert calls["snc_myname"] is None
    assert calls["snc_qop"] == 3  # D-12 default
    assert calls["snc_sso"] is False  # D-12 default


def test_connect_snc_qop_and_myname_flow_through(monkeypatch) -> None:
    """Explicit snc_qop / snc_myname / snc_sso flow through to SncTransport (D-12)."""
    import saprfclib.connection as _connmod
    import saprfclib.snc as _snc
    from saprfclib import connect as _connect

    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response").payload_bytes
    fake_snc = MockTransport(_handshake_responses()[1:])
    calls: dict[str, object] = {}

    monkeypatch.setattr(_connmod, "connect_tcp", lambda *a, **k: MockTransport([ni_resp]))

    def _fake_snc_transport(inner, **kwargs):
        calls.update(kwargs)
        return fake_snc

    monkeypatch.setattr(_snc, "SncTransport", _fake_snc_transport)

    _connect(
        ashost="sap.example",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
        snc_lib="/fake.so",
        snc_partnername="p:CN=S",
        snc_myname="p:CN=Client",
        snc_qop=2,
    )

    assert calls["snc_myname"] == "p:CN=Client"
    assert calls["snc_qop"] == 2
    assert calls["snc_sso"] is False


def test_connect_wshost_wins_over_snc_lib(monkeypatch) -> None:
    """When both wshost and snc_lib are set, the wRFC branch wins (SNC not taken).

    SNC-over-wRFC is out of scope for Phase 7; wshost is checked first and the
    SNC ``elif`` is never reached.
    """
    import saprfclib.snc as _snc
    import saprfclib.ws as _ws
    from saprfclib import connect as _connect

    fake_ws = MockTransport(_handshake_responses())

    monkeypatch.setattr(_ws, "connect_ws", lambda *a, **k: fake_ws)

    def _boom_snc(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("SncTransport must not be built when wshost is set")

    monkeypatch.setattr(_snc, "SncTransport", _boom_snc)

    conn = _connect(
        ashost="ignored",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
        wshost="bt.example",
        snc_lib="/fake.so",
        snc_partnername="p:CN=S",
    )

    assert conn._transport is fake_ws
    assert conn._session.state is SessionState.READY


def test_connect_plain_path_unchanged_when_snc_absent() -> None:
    """SEC-01: neither wshost nor snc_lib set → plain connect_tcp path, unchanged.

    Uses a MockTransport so no socket is touched; the plain path must still walk
    the handshake to READY exactly as before Phase 7.
    """
    transport = MockTransport(_handshake_responses())
    conn = Connection(transport)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    assert conn._session.state is SessionState.READY


def test_snc_error_on_public_surface() -> None:
    """SncError is importable from the top-level saprfclib package and in __all__."""
    import saprfclib
    from saprfclib import SncError
    from saprfclib.exceptions import SapRfcError

    assert "SncError" in saprfclib.__all__
    assert issubclass(SncError, SapRfcError)


def test_connect_snc_lib_never_in_exception(monkeypatch) -> None:
    """snc_lib / snc_partnername / snc_myname must never leak into a raised
    exception (T-07-CRED)."""
    import saprfclib.connection as _connmod
    import saprfclib.snc as _snc
    from saprfclib import connect as _connect

    secret_lib = "/opt/secret/libsapcrypto.so"
    secret_partner = "p:CN=SecretServer,O=SecretOrg"
    secret_myname = "p:CN=SecretClient"

    # NI exchange happens on the plain inner transport before SncTransport is
    # created — inner must support send_message/recv_message (T-07-CRED: only
    # _boom_snc needs to fire to test the credential-leak check).
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response").payload_bytes
    monkeypatch.setattr(_connmod, "connect_tcp", lambda *a, **k: MockTransport([ni_resp]))

    def _boom_snc(inner, **kwargs):
        raise RuntimeError("SNC handshake failed at GSS_S_CONTINUE_NEEDED")

    monkeypatch.setattr(_snc, "SncTransport", _boom_snc)

    with pytest.raises(RuntimeError) as excinfo:
        _connect(
            ashost="sap.example",
            sysnr="00",
            client="001",
            user="DEVELOPER",
            passwd="secret",
            snc_lib=secret_lib,
            snc_partnername=secret_partner,
            snc_myname=secret_myname,
        )
    msg = str(excinfo.value)
    assert secret_lib not in msg
    assert secret_partner not in msg
    assert secret_myname not in msg


def test_close_after_partial_handshake() -> None:
    """close() mid-handshake (state NI_VERSIONED) does not raise and still closes
    the transport (TRANS-06 partial/error state)."""
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response")
    transport = MockTransport([ni_resp.payload_bytes])
    conn = Connection(transport)
    # Drive only the first leg of the handshake.
    payload = conn._session.start()
    transport.send_message(payload)
    out = conn._session.feed(transport.recv_message())
    if out:
        transport.send_message(out)
    assert conn._session.state is SessionState.NI_VERSIONED
    conn.close()  # must not raise
    assert transport.closed is True
    assert conn._session.state is SessionState.CLOSED


# --------------------------------------------------------------------------- #
# V1 ngrfc Q-marker structural tests for non-CHAR rfctypes                    #
# (protocol analysis the type mapping + serializeSingleTypeMetaData       #
# + the field serializer — no live network required)             #
# --------------------------------------------------------------------------- #

import struct as _struct  # noqa: E402

from saprfclib.connection import (  # noqa: E402
    _V1_COL_NAME,
    _V1_NGT,
    _v1_enc_bcd,
    _v1_enc_int,
    _v1_enc_string,
    _v1_enc_xstring,
    _v1_encode_char_value,
    _v1_q_block,
    _v1_stringlike_chunks,
    _v1_tname,
)
from saprfclib.types import RFC_IMPORT, FieldDesc  # noqa: E402


def _fd(
    name: str, rfctype: int, nuc_length: int, decimals: int = 0, direction: int = RFC_IMPORT
) -> FieldDesc:
    uc_len = nuc_length * 2 if rfctype in (0, 1, 3, 6, 29, 30) else nuc_length
    return FieldDesc(
        name=name,
        rfctype=rfctype,
        nuc_length=nuc_length,
        nuc_offset=0,
        uc_length=uc_len,
        uc_offset=0,
        decimals=decimals,
        unicode_mode=True,
        direction=direction,
    )


def _parse_q_block(data: bytes) -> dict:
    """Parse a V1 Q-marker block into components for assertions."""
    assert data[0] == 0x51, "expected Q-marker"
    name_len = data[1]
    name = data[2 : 2 + name_len].decode()
    off = 2 + name_len
    assert data[off] == 0x44, "expected D-block marker"
    assert data[off + 1 : off + 3] == b"\x01\x50", "expected ncols 0x5001 LE"
    off += 3
    tname_len = data[off]
    tname = data[off + 1 : off + 1 + tname_len]
    off += 1 + tname_len
    ngrfc_type = data[off]
    return {
        "name": name,
        "tname": tname,
        "ngrfc_type": ngrfc_type,
        "rest_off": off + 1,
        "data": data,
    }


def _parse_d_rest(q: dict) -> dict:
    """After ngrfc_type, read optional field_len and col_name from D-block."""
    data = q["data"]
    off = q["rest_off"]
    ngt = q["ngrfc_type"]
    field_len = None
    decimals_byte = None
    if ngt > 4:
        if ngt == 9:  # BCD: int2 field_len + byte decimals
            field_len = _struct.unpack_from("<H", data, off)[0]
            off += 2
            decimals_byte = data[off]
            off += 1
        else:  # int2 field_len
            field_len = _struct.unpack_from("<H", data, off)[0]
            off += 2
    col_name_len = data[off]
    col_name = data[off + 1 : off + 1 + col_name_len]
    value_off = off + 1 + col_name_len
    return {
        "field_len": field_len,
        "decimals": decimals_byte,
        "col_name": col_name,
        "value": data[value_off:],
    }


class TestV1QBlockInts:
    def test_int4_d_block(self) -> None:
        """INT4 (rfctype=8): ngrfc_type=3, no field_len, compMode=0x4E, 4B LE."""
        blk = _v1_q_block(b"MYINT", b"\\TYPE=INT4", 3, None, b"\x4e" + _struct.pack("<i", 42))
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 3
        assert d["field_len"] is None
        assert d["col_name"] == _V1_COL_NAME
        assert d["value"] == b"\x4e" + _struct.pack("<i", 42)

    def test_int2_d_block(self) -> None:
        """INT2 (rfctype=9): ngrfc_type=2, no field_len."""
        blk = _v1_q_block(b"I2", b"\\TYPE=INT2", 2, None, b"\x4e" + _struct.pack("<h", -5))
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 2
        assert d["field_len"] is None
        assert d["value"] == b"\x4e" + _struct.pack("<h", -5)

    def test_int1_d_block(self) -> None:
        """INT1 (rfctype=10): ngrfc_type=1, no field_len, unsigned."""
        blk = _v1_q_block(b"I1", b"\\TYPE=INT1", 1, None, b"\x4e\xff")
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 1
        assert d["field_len"] is None
        assert d["value"] == b"\x4e\xff"

    def test_int8_d_block(self) -> None:
        """INT8 (rfctype=31): ngrfc_type=4, no field_len."""
        val = _v1_enc_int(2**40, 8, True)
        blk = _v1_q_block(b"I8", b"\\TYPE=INT8", 4, None, val)
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 4
        assert d["field_len"] is None

    def test_utclong_d_block(self) -> None:
        """UTCLONG (rfctype=32): ngrfc_type=29 (0x1d), field_len=8, INT8 wire encoding.

        the type mapping case 0x20 → ngrfc_type=0x1d.
        the field serializer case 0x1f,0x20 → shared INT8 path (compMode=0x4e + int64LE).
        ngrfc_type 29 > 4 → field_len IS written in D-block (unlike INT8's ngrfc_type=4).
        """
        ts = 1_000_000_000  # arbitrary UTCLONG value (nanoseconds)
        val = _v1_enc_int(ts, 8, True)
        blk = _v1_q_block(b"TS", b"\\TYPE=UTCLONG", 29, 8, val)
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 29
        assert d["field_len"] == 8
        assert d["col_name"] == _V1_COL_NAME
        assert d["value"][0] == 0x4E  # compMode 'N'
        assert _struct.unpack_from("<q", d["value"], 1)[0] == ts

    def test_enc_int_values(self) -> None:
        """_v1_enc_int round-trips positive and negative values."""
        assert _v1_enc_int(0, 4, True) == b"\x4e\x00\x00\x00\x00"
        assert _v1_enc_int(-1, 2, True) == b"\x4e\xff\xff"
        assert _v1_enc_int(255, 1, False) == b"\x4e\xff"
        assert _v1_enc_int(2**31 - 1, 4, True) == b"\x4e\xff\xff\xff\x7f"


class TestV1QBlockFloat:
    def test_float_d_block(self) -> None:
        """FLOAT (rfctype=7): ngrfc_type=19 (0x13), field_len=8, compMode=0x4E."""
        val = b"\x4e" + _struct.pack("<d", 3.14)
        blk = _v1_q_block(b"FLT", b"\\TYPE=FLTP", 19, 8, val)
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 19
        assert d["field_len"] == 8
        assert d["col_name"] == _V1_COL_NAME
        assert _struct.unpack_from("<d", d["value"], 1)[0] == pytest.approx(3.14)


class TestV1QBlockBcd:
    def test_bcd_d_block_structure(self) -> None:
        """BCD (rfctype=2): ngrfc_type=9, field_len int2 + decimals byte in D-block."""
        val = _v1_enc_bcd("12.34", 4, 2)
        blk = _v1_q_block(b"AMT", b"\\TYPE=P4", 9, 4, val, decimals=2)
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 9
        assert d["field_len"] == 4
        assert d["decimals"] == 2
        assert d["col_name"] == _V1_COL_NAME
        assert d["value"][0] == 0x4E  # compMode

    def test_bcd_encode_positive(self) -> None:
        """Packed BCD: 12.34 with 4B P(2 decimals) → 0x00 0x12 0x34 0xC (positive)."""
        result = _v1_enc_bcd("12.34", 4, 2)
        # 4 bytes: nuc_length=4, decimals=2
        # digits: 000001234 (7 digits), sign=0xC → nibbles 0 0 0 0 1 2 3 4 C
        assert result[0] == 0x4E
        assert result[1:] == bytes([0x00, 0x00, 0x12, 0x34]) or result[1:] == bytes(
            [0x00, 0x01, 0x23, 0x4C]
        )

    def test_bcd_encode_negative(self) -> None:
        """Negative BCD value uses sign nibble 0xD."""
        from decimal import Decimal

        result = _v1_enc_bcd(Decimal("-1"), 2, 0)
        assert result[0] == 0x4E
        assert result[-1] & 0x0F == 0xD  # last nibble = 0xD (negative)

    def test_bcd_encode_zero(self) -> None:
        """BCD zero: all digit nibbles 0, sign nibble 0xC."""
        result = _v1_enc_bcd(0, 2, 0)
        assert result == b"\x4e\x00\x0c"

    def test_bcd_overflow_raises(self) -> None:
        """Value too large for field raises OverflowError."""
        with pytest.raises(OverflowError):
            _v1_enc_bcd(99999, 2, 0)  # P(2) max = 999 (3 digits)


class TestV1QBlockString:
    def test_string_d_block(self) -> None:
        """STRING (rfctype=29): ngrfc_type=24 (0x18), field_len=0, compMode=0x53.

        the string serializer non-UC single chunk:
        chunk_hdr = utf8_byte_count | 0x4000 (last-chunk flag for first chunk in non-UC mode).
        """
        val = _v1_enc_string("hello")
        blk = _v1_q_block(b"TXT", b"\\TYPE=STRING", 24, 0, val)
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 24
        assert d["field_len"] == 0
        assert d["value"][0] == 0x53  # compMode 'S'
        chunk_hdr = _struct.unpack_from("<H", d["value"], 1)[0]
        assert chunk_hdr == len(b"hello") | 0x4000  # byte_count | last-chunk flag
        assert d["value"][3:] == b"hello"

    def test_string_empty(self) -> None:
        """Empty STRING: compMode 'S' + int2(0 | 0x4000) — last-chunk flag set even for empty."""
        result = _v1_enc_string("")
        assert result == b"\x53\x00\x40"  # 0x4000 flag: byte_count=0, flag=0x4000 → LE 00 40

    def test_xstring_d_block(self) -> None:
        """XSTRING (rfctype=30): ngrfc_type=25 (0x19), field_len=0, compMode=0x58.

        the string serializer non-UC single chunk: chunk_hdr = byte_count | 0x4000.
        """
        raw = b"\xde\xad\xbe\xef"
        val = _v1_enc_xstring(raw)
        blk = _v1_q_block(b"RAW", b"\\TYPE=XSTRING", 25, 0, val)
        q = _parse_q_block(blk)
        d = _parse_d_rest(q)
        assert q["ngrfc_type"] == 25
        assert d["field_len"] == 0
        assert d["value"][0] == 0x58  # compMode 'X'
        chunk_hdr = _struct.unpack_from("<H", d["value"], 1)[0]
        assert chunk_hdr == len(raw) | 0x4000  # byte_count | last-chunk flag
        assert d["value"][3:] == raw


class TestV1StringlikeChunks:
    """Unit tests for _v1_stringlike_chunks (multi-chunk the string serializer helper)."""

    def test_empty(self) -> None:
        """Empty data → single chunk with 0x4000 flag."""
        result = _v1_stringlike_chunks(b"")
        assert result == _struct.pack("<H", 0x4000)

    def test_single_chunk_small(self) -> None:
        """Small data fits in one first chunk (≤ 0x3FFF): hdr = byte_count | 0x4000."""
        data = b"hello"
        result = _v1_stringlike_chunks(data)
        hdr = _struct.unpack_from("<H", result)[0]
        assert hdr == len(data) | 0x4000
        assert result[2:] == data

    def test_single_chunk_max(self) -> None:
        """Exactly 0x3FFF bytes → still single chunk."""
        data = b"x" * 0x3FFF
        result = _v1_stringlike_chunks(data)
        hdr = _struct.unpack_from("<H", result)[0]
        assert hdr == 0x3FFF | 0x4000
        assert result[2:] == data

    def test_two_chunks(self) -> None:
        """0x3FFF + 1 bytes → two chunks: first hdr=0x3FFF (no flag), last hdr=1|0x8000."""
        data = b"a" * 0x3FFF + b"b"
        result = _v1_stringlike_chunks(data)
        # First chunk header: 0x3FFF, no flag
        hdr1 = _struct.unpack_from("<H", result, 0)[0]
        assert hdr1 == 0x3FFF
        assert result[2 : 2 + 0x3FFF] == b"a" * 0x3FFF
        # Second chunk header: 1 | 0x8000 (last, subsequent)
        off2 = 2 + 0x3FFF
        hdr2 = _struct.unpack_from("<H", result, off2)[0]
        assert hdr2 == 1 | 0x8000
        assert result[off2 + 2 :] == b"b"

    def test_utf8_boundary_not_split(self) -> None:
        """Multi-byte UTF-8 sequence straddling chunk boundary is kept intact."""
        # Build data where a 3-byte UTF-8 char (€ = 0xE2 0x82 0xAC) sits at boundary
        prefix = b"a" * (0x3FFF - 1)  # 16382 bytes, then 3-byte char would split at 16383
        three_byte = "€".encode()  # 3 bytes
        data = prefix + three_byte + b"z"
        result = _v1_stringlike_chunks(data)
        hdr1 = _struct.unpack_from("<H", result, 0)[0]
        # First chunk must end before the 3-byte sequence (trim back 2 bytes)
        assert hdr1 == len(prefix)  # = 0x3FFE, no flag
        chunk1_end = 2 + hdr1
        # Second chunk holds the 3-byte char + 'z'
        hdr2 = _struct.unpack_from("<H", result, chunk1_end)[0]
        assert hdr2 == (len(three_byte) + 1) | 0x8000
        assert result[chunk1_end + 2 :] == three_byte + b"z"


class TestV1EncodeCharValueLarge:
    """Tests for the large CHAR path (uc_length > 0x3333) in _v1_encode_char_value.

    the field serializer case 0: compMode='S' when uc_length > 0x3333; calls the string serializer.
    """

    def test_large_char_compmode_s(self) -> None:
        """uc_length > 0x3333 → compMode byte must be 0x53 ('S')."""
        result = _v1_encode_char_value("hello", nuc_length=6554, uc_length=0x3334)
        assert result[0] == 0x53

    def test_large_char_single_chunk_flag(self) -> None:
        """Short value in large CHAR field → single chunk with 0x4000 last-flag."""
        val = "ABC"
        result = _v1_encode_char_value(val, nuc_length=7000, uc_length=14000)
        assert result[0] == 0x53  # compMode 'S'
        hdr = _struct.unpack_from("<H", result, 1)[0]
        utf8_len = len(val.encode("utf-8"))
        assert hdr == utf8_len | 0x4000

    def test_large_char_strips_trailing_spaces(self) -> None:
        """Trailing spaces stripped before encoding (same as 'C' path)."""
        result = _v1_encode_char_value("AB  ", nuc_length=6554, uc_length=0x3334)
        assert result[0] == 0x53
        hdr = _struct.unpack_from("<H", result, 1)[0]
        assert hdr == len(b"AB") | 0x4000
        assert result[3:] == b"AB"

    def test_boundary_uc_3333_uses_c_path(self) -> None:
        """uc_length exactly 0x3333 → still 'C' path (not 'S')."""
        result = _v1_encode_char_value("x", nuc_length=1, uc_length=0x3333)
        assert result[0] == 0x43  # compMode 'C'

    def test_boundary_uc_3334_uses_s_path(self) -> None:
        """uc_length exactly 0x3334 → 'S' path."""
        result = _v1_encode_char_value("x", nuc_length=1, uc_length=0x3334)
        assert result[0] == 0x53  # compMode 'S'


class TestV1Tname:
    def test_fixed_type_names(self) -> None:
        assert _v1_tname(1, 8) == b"\\TYPE=DATS"
        assert _v1_tname(3, 6) == b"\\TYPE=TIMS"
        assert _v1_tname(7, 8) == b"\\TYPE=FLTP"
        assert _v1_tname(8, 4) == b"\\TYPE=INT4"
        assert _v1_tname(9, 2) == b"\\TYPE=INT2"
        assert _v1_tname(10, 1) == b"\\TYPE=INT1"
        assert _v1_tname(31, 8) == b"\\TYPE=INT8"
        assert _v1_tname(29, 0) == b"\\TYPE=STRING"
        assert _v1_tname(30, 0) == b"\\TYPE=XSTRING"

    def test_length_suffix_types(self) -> None:
        assert _v1_tname(0, 30) == b"\\TYPE=CHAR30"
        assert _v1_tname(2, 8) == b"\\TYPE=P8"
        assert _v1_tname(4, 4) == b"\\TYPE=X4"
        assert _v1_tname(6, 10) == b"\\TYPE=NUMC10"


class TestV1NgtMapping:
    def test_unicode_mode_ngrfc_types(self) -> None:
        """the type mapping (Unicode mode) mapping."""
        assert _V1_NGT[0] == 6  # CHAR → CHAR_UC
        assert _V1_NGT[1] == 12  # DATE → DATE_UC
        assert _V1_NGT[2] == 9  # BCD
        assert _V1_NGT[3] == 14  # TIME → TIME_UC
        assert _V1_NGT[4] == 23  # BYTE (X)
        assert _V1_NGT[6] == 8  # NUM → NUMC_UC
        assert _V1_NGT[7] == 19  # FLOAT
        assert _V1_NGT[8] == 3  # INT4
        assert _V1_NGT[9] == 2  # INT2
        assert _V1_NGT[10] == 1  # INT1
        assert _V1_NGT[29] == 24  # STRING
        assert _V1_NGT[30] == 25  # XSTRING
        assert _V1_NGT[31] == 4  # INT8
        assert _V1_NGT[32] == 29  # UTCLONG → ngrfc_type 0x1d ( case 0x20)


# --------------------------------------------------------------------------- #
# RFCPING response parsing (issue #7)
# --------------------------------------------------------------------------- #
#
# _rfcping_ok reads the same wire dialect as every other TLV reader in the tree:
# live responses arrive as GW frames, records may use the extended-length form,
# and each record is followed by a repeated close tag. The synthetic fixture at
# the top of this module happens to place 0x0420 first in a simple-format stream,
# which is why the pre-fix parser passed while failing on real responses.


def _tlv_closed(tag: int, value: bytes) -> bytes:
    """Extended TLV record: tag + len + value + repeated tag (live server format)."""
    return struct.pack(">HH", tag, len(value)) + value + struct.pack(">H", tag)


def _gw_frame(tlv_body: bytes) -> bytes:
    """Wrap a TLV stream in a GW frame: 76-byte header + 4-byte RFC marker."""
    return b"\x06\xcb" + b"\x00" * 74 + b"\xff\xff\x00\x01" + tlv_body


def test_rfcping_ok_reads_return_code_after_leading_records() -> None:
    """0x0420 is not always first — the walk must survive records before it."""
    body = (
        _tlv_closed(0x0500, b"")
        + _tlv_closed(0x0503, b"")
        + _tlv_closed(0x0514, b"\x11" * 16)
        + _tlv_closed(0x0420, struct.pack(">I", 0))
        + _tlv_closed(0xFFFF, b"")
    )
    assert Connection._rfcping_ok(body) is True


def test_rfcping_ok_strips_the_gw_header() -> None:
    """A live response is a GW frame; parsing it raw reads header bytes as tags."""
    body = (
        _tlv_closed(0x0500, b"")
        + _tlv_closed(0x0420, struct.pack(">I", 0))
        + _tlv_closed(0xFFFF, b"")
    )
    assert Connection._rfcping_ok(_gw_frame(body)) is True


def test_rfcping_ok_handles_extended_length_records() -> None:
    """A record >= 0xFFFF bytes uses the 0xFFFF marker + 4-byte BE length."""
    big = b"\x5a" * 0x10000
    body = (
        struct.pack(">HH", 0x0402, 0xFFFF)
        + struct.pack(">I", len(big))
        + big
        + struct.pack(">H", 0x0402)
        + _tlv_closed(0x0420, struct.pack(">I", 0))
        + _tlv_closed(0xFFFF, b"")
    )
    assert Connection._rfcping_ok(_gw_frame(body)) is True


def test_rfcping_reports_a_nonzero_return_code() -> None:
    body = (
        _tlv_closed(0x0500, b"")
        + _tlv_closed(0x0420, struct.pack(">I", 163))
        + _tlv_closed(0xFFFF, b"")
    )
    assert Connection._rfcping_ok(_gw_frame(body)) is False


def test_rfcping_still_rejects_a_genuinely_truncated_record() -> None:
    """Bounds checking stays in force — a real overrun must still raise."""
    truncated = struct.pack(">HH", 0x0402, 512) + b"\x00" * 8
    with pytest.raises(ValueError, match="exceeds remaining payload"):
        Connection._rfcping_ok(truncated)


def test_rfcping_raises_when_no_return_code_is_present() -> None:
    body = _tlv_closed(0x0500, b"") + _tlv_closed(0xFFFF, b"")
    with pytest.raises(ValueError, match="missing return-code"):
        Connection._rfcping_ok(_gw_frame(body))


# --------------------------------------------------------------------------- #
# Logon language (issue #8)
# --------------------------------------------------------------------------- #


def test_logon_request_carries_the_requested_language() -> None:
    """Tag 0x0011 holds the one-character SAP code as a single ASCII byte.

    Source: golden fixture tests/golden/framing/logon_request.json (rfc_lang 'E').
    """
    tlv = Connection._build_logon_request(
        client="001", user="DEVELOPER", passwd="secret", lang="D", seed=1
    )
    assert _tlv_ext_value(tlv, 0x0011) == b"D"


def test_logon_language_defaults_to_english() -> None:
    tlv = Connection._build_logon_request(client="001", user="DEVELOPER", passwd="secret", seed=1)
    assert _tlv_ext_value(tlv, 0x0011) == b"E"


def test_logon_language_is_uppercased() -> None:
    tlv = Connection._build_logon_request(
        client="001", user="DEVELOPER", passwd="secret", lang="d", seed=1
    )
    assert _tlv_ext_value(tlv, 0x0011) == b"D"


@pytest.mark.parametrize(("given", "expected"), [("EN", b"E"), ("DE", b"D"), ("ES", b"S")])
def test_two_character_iso_codes_are_converted_before_the_wire(given: str, expected: bytes) -> None:
    """SDK parity: LANG accepts an ISO code, the frame still carries one character."""
    from saprfclib.connection import _encode_logon_language

    assert _encode_logon_language(given) == expected


@pytest.mark.parametrize("bad", ["", "ENG", "xx"])
def test_unusable_language_codes_are_rejected(bad: str) -> None:
    """Wrong length, or a two-character code naming no known SAP language."""
    from saprfclib.connection import _encode_logon_language

    with pytest.raises(ValueError):
        _encode_logon_language(bad)


def test_logon_request_accepts_an_iso_language() -> None:
    """connect(lang="EN") reaches the wire as b"E" on both language tags."""
    tlv = Connection._build_logon_request(
        client="001", user="DEVELOPER", passwd="secret", lang="EN", seed=1
    )
    assert _tlv_ext_value(tlv, 0x0115) == b"E"
    assert _tlv_ext_value(tlv, 0x0011) == b"E"


def test_connect_accepts_lang_keyword() -> None:
    """connect()/connect_async() expose lang so C SDK callers can migrate."""
    import inspect

    from saprfclib.connection import connect, connect_async

    assert "lang" in inspect.signature(connect).parameters
    assert "lang" in inspect.signature(connect_async).parameters


def _tlv_ext_value(stream: bytes, want: int) -> bytes:
    """Return the first value for `want` in an extended-format TLV stream."""
    pos, n = 0, len(stream)
    while pos + 4 <= n:
        tag, length = struct.unpack_from(">HH", stream, pos)
        pos += 4
        if tag == 0xFFFF:
            break
        if length == 0xFFFF:
            length = struct.unpack_from(">I", stream, pos)[0]
            pos += 4
        val = stream[pos : pos + length]
        pos += length
        if pos + 2 <= n and struct.unpack_from(">H", stream, pos)[0] == tag:
            pos += 2
        if tag == want:
            return val
    raise AssertionError(f"tag 0x{want:04x} not found")


def test_logon_request_sets_language_on_both_tags() -> None:
    """0x0115 and 0x0011 both carry the language byte.

    Source: golden fixture tests/golden/framing/logon_request.bin — both tags hold
    b"E" for a logon in English.
    """
    tlv = Connection._build_logon_request(
        client="001", user="DEVELOPER", passwd="secret", lang="D", seed=1
    )
    assert _tlv_ext_value(tlv, 0x0115) == b"D"
    assert _tlv_ext_value(tlv, 0x0011) == b"D"


def test_golden_logon_fixture_carries_the_language_on_both_tags() -> None:
    """Pin the expectation to the capture itself, not just to our builder."""
    fixture = load_fixture(GOLDEN_ROOT / "framing", "logon_request")
    # ni(4) + gw header(76) + rfc marker(4) + com_head(12) = 96
    tlv = fixture.raw_bytes[96:]
    assert _tlv_ext_value(tlv, 0x0115) == b"E"
    assert _tlv_ext_value(tlv, 0x0011) == b"E"


# --------------------------------------------------------------------------- #
# RFCPING request framing (issue #7, second defect)
# --------------------------------------------------------------------------- #
#
# The probe must be a fully framed invoke, identical in shape to any other call.
# It used to be a bare TLV body sent straight to the transport, which reaches the
# gateway as a malformed frame: the server reads the function name where it expects
# a 76-byte GW header and answers with a plain-text error instead of a response.
# Offline tests missed it because MockTransport never validated what was sent.


def test_ping_sends_a_gw_framed_invoke() -> None:
    """The bytes on the wire must carry GW header, RFC marker, TLV body and footer."""
    conn, transport = _ready_connection(extra=[_rfcping_ok()])
    before = len(transport.sent)
    conn.ping()

    frame = transport.sent[before]
    assert frame[0:2] == b"\x06\xcb", "missing GW frame type"
    assert frame[2:4] == b"\x02\x00", "missing GW version"
    # Omitting the APPC header version draws an immediate 0x06CE rejection.
    assert struct.unpack_from(">I", frame, 24)[0] == 8
    assert frame[76:80] == b"\xff\xff\x00\x04", "missing RFC marker"
    assert len(frame) > 80, "frame carries no TLV body"


def test_ping_request_tlv_matches_the_invoke_layout() -> None:
    """Same record sequence as the golden invoke request, minus params.

    Golden rfc_read_table_request.bin opens 0x0502 → 0x000b → 0x0102 → 0x0512 and
    then carries its parameters; RFCPING takes none, so it terminates right after.
    """
    tlv = Connection._rfcping_request_tlv()
    tags = [tag for tag, _ in _walk_invoke_tlv(tlv)]
    assert tags == [0x0502, 0x000B, 0x0102, 0x0512]

    values = dict(_walk_invoke_tlv(tlv))
    assert values[0x0102].decode("utf-16-le") == "RFCPING"
    assert values[0x000B].decode("utf-16-le") == "754"


def test_ping_function_name_is_utf16le_not_ascii() -> None:
    """The old probe sent b"RFCPING" raw; the invoke TLV is UTF-16LE throughout."""
    tlv = Connection._rfcping_request_tlv()
    assert b"R\x00F\x00C\x00P\x00I\x00N\x00G\x00" in tlv
    assert b"RFCPING" not in tlv


def test_ping_frame_footer_declares_the_tlv_length() -> None:
    """Invoke footer is 0x0000 | len(tlv) BE16 | 0x0000 | 0x8500."""
    tlv = Connection._rfcping_request_tlv()
    frame = Connection._build_invoke_frame(b"12345678", tlv)
    footer = frame[-8:]
    assert struct.unpack_from(">H", footer, 2)[0] == len(tlv)
    assert footer[6:8] == b"\x85\x00"


def _walk_invoke_tlv(data: bytes) -> list[tuple[int, bytes]]:
    """Walk an invoke TLV body, skipping close tags, stopping at the terminator."""
    out: list[tuple[int, bytes]] = []
    pos, n = 0, len(data)
    while pos + 4 <= n:
        tag, length = struct.unpack_from(">HH", data, pos)
        pos += 4
        if tag == 0xFFFF:
            break
        if length == 0xFFFF:
            length = struct.unpack_from(">I", data, pos)[0]
            pos += 4
        val = data[pos : pos + length]
        pos += length
        if pos + 2 <= n and struct.unpack_from(">H", data, pos)[0] == tag:
            pos += 2
        out.append((tag, val))
    return out


# --------------------------------------------------------------------------- #
# RFCPING golden replay (issue #7)
# --------------------------------------------------------------------------- #
#
# Captured from a live A4H system (kernel 793 / release 758) at the transport seam,
# so these frames carry no NI length prefix — they start at the GW header.
# Sanitised preserving byte length: GW handle and session token substituted.

FRAMING_DIR = GOLDEN_ROOT / "framing"


def test_rfcping_request_matches_the_golden_capture_byte_for_byte() -> None:
    """Our invoke builder reproduces the live RFCPING request exactly."""
    fixture = load_fixture(FRAMING_DIR, "rfcping_request")
    handle = fixture.raw_bytes[40:48]  # sanitised handle, preserved in place
    built = Connection._build_invoke_frame(handle, Connection._rfcping_request_tlv())
    assert built == fixture.raw_bytes


def test_rfcping_golden_response_parses_as_success() -> None:
    """The live response reports rc=0, and _rfcping_ok reads it."""
    fixture = load_fixture(FRAMING_DIR, "rfcping_response")
    assert Connection._rfcping_ok(fixture.raw_bytes) is True


def test_rfcping_golden_response_puts_the_return_code_fourth() -> None:
    """The property that broke the old parser.

    0x0420 sits behind 0x0500, 0x0503 and a 16-byte 0x0514 session token, each
    followed by a repeated close tag. Skipping the close tag is what keeps the walk
    aligned long enough to reach the return code.
    """
    fixture = load_fixture(FRAMING_DIR, "rfcping_response")
    tags = [tag for tag, _ in _walk_invoke_tlv(fixture.raw_bytes[80:])]
    assert tags[:4] == [0x0500, 0x0503, 0x0514, 0x0420]


def test_rfcping_golden_response_uses_the_server_direction_marker() -> None:
    """Responses carry 00000002 at [76:80], not the client's ffff0004.

    The 80-byte strip keys off the leading 0x06 GW byte, so it is unaffected.
    """
    fixture = load_fixture(FRAMING_DIR, "rfcping_response")
    assert fixture.raw_bytes[0] == 0x06
    assert fixture.raw_bytes[76:80] == b"\x00\x00\x00\x02"
    request = load_fixture(FRAMING_DIR, "rfcping_request")
    assert request.raw_bytes[76:80] == b"\xff\xff\x00\x04"


def test_unstripped_gw_header_is_what_issue_7_reported() -> None:
    """Reading the GW header as TLV yields 'length 512' — gw_version 0x0200.

    Pins the exact failure signature from the issue report, so a regression is
    recognisable rather than just red.
    """
    fixture = load_fixture(FRAMING_DIR, "rfcping_response")
    raw = fixture.raw_bytes
    assert struct.unpack_from(">H", raw, 2)[0] == 512  # the bogus "length"
    # With the header stripped the same bytes parse cleanly.
    assert Connection._rfcping_ok(raw) is True
