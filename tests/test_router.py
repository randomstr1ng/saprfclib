# tests/test_router.py
#
# Offline tests for the SAProuter route-string parser, the NI_ROUTE prefix
# builder, MessageServerClient.resolve (Plan 03-03 Task 2, TRANS-02/03), and
# the full SAPMS MESSAGE server-list frame parser (Plan 04-03, TRANS-03).
#
# The route-string parser is deterministic, pure string parsing — fully
# verifiable offline. The NI_ROUTE-prefix and message-server-resolve byte
# layouts are [ASSUMED] (pysap-documented / RESEARCH A1/A2, not byte-verified):
# these tests assert STRUCTURAL shape only. Proving the bytes is the job of the
# plan 03-03 Task 3 blocking human-verify checkpoint, NOT of this test module.
#
# The SAPMS MESSAGE frame parser tests (Plan 04-03) use a golden fixture from a
# live capture: tests/golden/router/sapms_server_list.bin. That fixture is
# byte-exact from captures/phase03_msgserver_capture_output.txt (wire-captured
# 2026-06-27, TRANS-03). The per-server entry layout fields annotated [ASSUMED]
# in the sidecar .json are structural inferences from the wire bytes — they are
# correct as byte-math but their semantic purpose is [ASSUMED].

import struct
from pathlib import Path

import pytest

from saprfclib.router import (
    MessageServerClient,
    RouteHop,
    build_ni_route,
    parse_route_string,
    parse_sapms_server_list,
)
from tests._mocks import MockTransport


# --------------------------------------------------------------------------- #
# Route-string parser (deterministic, offline)
# --------------------------------------------------------------------------- #
def test_parse_route_string_single_hop() -> None:
    """A single /H/host/S/service hop parses into one typed RouteHop with the
    talk-mode/password fields defaulted."""
    hops = parse_route_string("/H/host/S/3299/H/saprouter")
    assert isinstance(hops, list)
    assert len(hops) == 2
    assert isinstance(hops[0], RouteHop)
    assert hops[0].host == "host"
    assert hops[0].service == "3299"
    assert hops[1].host == "saprouter"
    # Defaults applied.
    assert hops[0].password == ""
    assert hops[0].talk_mode == 0


def test_parse_route_string_multi_hop() -> None:
    """A 3-hop chain parses into 3 ordered hops; malformed/empty input raises."""
    hops = parse_route_string("/H/a/S/3299/H/b/S/3298/H/c")
    assert [h.host for h in hops] == ["a", "b", "c"]

    with pytest.raises(ValueError):
        parse_route_string("")
    with pytest.raises(ValueError):
        parse_route_string("not-a-route-string")


def test_build_ni_route_prefix_shape() -> None:
    """build_ni_route confirmed format from live capture 2026-06-27 (TRANS-02).

    NI_ROUTE\\0 (9B) + talk_mode(0x02) + 0x28 + version(0x02) +
    hop_count(4B BE) + total_data(4B BE) + per-hop entries + final dest.
    """
    hops = parse_route_string("/H/host/S/3299/H/saprouter")
    frame = build_ni_route(hops, "myapp", "3300")
    assert isinstance(frame, (bytes, bytearray))
    # Magic: "NI_ROUTE\0" (9 bytes, null-terminated)
    assert frame.startswith(b"NI_ROUTE\x00")
    # talk_mode = 0x02, fixed byte = 0x28, version = 0x02
    assert frame[9] == 0x02
    assert frame[10] == 0x28
    assert frame[11] == 0x02
    # hop_count = 2 (4 bytes BE at offset 12)
    hop_count = struct.unpack_from(">I", frame, 12)[0]
    assert hop_count == 2
    # Host strings appear in payload (null-terminated)
    assert b"host\x00" in frame
    assert b"saprouter\x00" in frame
    assert b"myapp\x00" in frame


def test_build_ni_route_golden() -> None:
    """NI_ROUTE payload matches byte-exact golden fixture from live capture 2026-06-27.

    Route: /H/saprouter.example.com/S/3299 → dest 192.168.88.7:3300
    Fixture: tests/golden/router/ni_route_payload.bin (71 bytes)
    """
    from pathlib import Path

    fixture = Path(__file__).parent / "golden" / "router" / "ni_route_payload.bin"
    expected = fixture.read_bytes()

    hops = parse_route_string("/H/saprouter.example.com/S/3299")
    actual = build_ni_route(hops, "192.168.88.7", "3300")
    assert actual == expected, (
        f"NI_ROUTE bytes mismatch\nexpected: {expected.hex()}\nactual:   {actual.hex()}"
    )


# --------------------------------------------------------------------------- #
# Message-server resolve ([ASSUMED] redirect, MockTransport-driven)
# --------------------------------------------------------------------------- #
def _ms_redirect(ashost: str, sysnr: int) -> bytes:
    """Synthetic [ASSUMED] message-server group-logon redirect response.

    Shape (the contract resolve() parses): the app-server host as a
    length-prefixed ASCII field followed by a 2-byte big-endian system number.
    """
    host_bytes = ashost.encode("ascii")
    return len(host_bytes).to_bytes(2, "big") + host_bytes + struct.pack(">H", sysnr)


def test_message_server_resolve_returns_host_port() -> None:
    """resolve(group), driven by a scripted [ASSUMED] redirect response, returns
    (ashost, sysnr)."""
    transport = MockTransport([_ms_redirect("vhcala4hci", 0)])
    client = MessageServerClient(transport)
    ashost, sysnr = client.resolve("PUBLIC")
    assert ashost == "vhcala4hci"
    assert sysnr == 0


def test_message_server_resolve_rejects_malformed() -> None:
    """A malformed/empty redirect response raises ValueError."""
    transport = MockTransport([b""])
    client = MessageServerClient(transport)
    with pytest.raises(ValueError):
        client.resolve("PUBLIC")


# --------------------------------------------------------------------------- #
# connect() wiring through router.py (MockTransport-driven, no live socket)
# --------------------------------------------------------------------------- #
def _handshake_script() -> list[bytes]:
    """The four scripted server frames that drive a Connection to READY."""
    from tests.conftest import GOLDEN_ROOT, load_fixture
    from tests.test_connection import _logon_response

    hd = GOLDEN_ROOT / "handshake"
    return [
        load_fixture(hd, "ni_version_response").payload_bytes,
        load_fixture(hd, "gw_connect_response").payload_bytes,
        load_fixture(hd, "gw_done_server").payload_bytes,
        _logon_response(rc=0),
    ]


def test_connect_saprouter_routes_through_router(monkeypatch) -> None:
    """connect(..., saprouter=...) prepends a NI_ROUTE frame (build_ni_route) and
    then completes the normal handshake — verified offline via MockTransport."""
    import saprfclib.connection as connection

    transport = MockTransport(_handshake_script())
    monkeypatch.setattr(connection, "connect_tcp", lambda host, port, timeout=None: transport)

    conn = connection.connect(
        ashost="app",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
        saprouter="/H/host/S/3299/H/saprouter",
    )
    # First sent frame is the NI_ROUTE prefix from router.build_ni_route.
    assert transport.sent[0].startswith(b"NI_ROUTE")
    assert conn.get_connection_attributes().sys_id == "A4H"


def test_connect_message_server_resolves_then_connects(monkeypatch) -> None:
    """connect(..., mshost=..., group=...) resolves via MessageServerClient then
    runs the direct-TCP handshake against the resolved (ashost, sysnr)."""
    import saprfclib.connection as connection

    ms_transport = MockTransport([_ms_redirect("vhcala4hci", 0)])
    app_transport = MockTransport(_handshake_script())
    handed_out = [ms_transport, app_transport]

    def fake_connect_tcp(host, port, timeout=None):
        return handed_out.pop(0)

    monkeypatch.setattr(connection, "connect_tcp", fake_connect_tcp)

    conn = connection.connect(
        ashost="ignored",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
        mshost="mshost",
        group="PUBLIC",
    )
    # The message-server side connection was closed after resolve.
    assert ms_transport.closed is True
    assert conn.get_connection_attributes().sys_id == "A4H"


# --------------------------------------------------------------------------- #
# SAPMS MESSAGE server-list frame parser (Plan 04-03, TRANS-03)
# Golden fixture: tests/golden/router/sapms_server_list.bin
# All wire constants are [wire-captured] from 2026-06-27 SAP A4H Rel. 758.
# Per-entry semantic field names annotated [ASSUMED] in the sidecar .json.
# --------------------------------------------------------------------------- #

_GOLDEN_ROOT = Path(__file__).parent / "golden" / "router"


def _golden_frame() -> bytes:
    """Load the golden SAPMS server-list frame (598 bytes, includes NI prefix)."""
    return (_GOLDEN_ROOT / "sapms_server_list.bin").read_bytes()


def _make_minimal_sapms_frame(ip_addr: str, port: int) -> bytes:
    """Build a minimal valid SAPMS server-list frame with exactly 1 entry.

    This is a synthetic frame for testing the parser and resolve() bounds checks.
    The frame header is copied from the golden fixture (valid magic/version/fields).
    One 160-byte per-server entry is appended. Not a wire-captured frame — structure
    matches the confirmed entry layout from the golden fixture analysis.
    """
    import socket as _socket

    # Header: copy from golden frame (bytes 0..117) — valid magic and opcode fields
    header = bytearray(_golden_frame()[:118])

    # Build one 160-byte entry with the requested IP and port
    entry = bytearray(160)
    # instance_name [0:40]: '-' padded
    entry[0:40] = b"-" + b" " * 39
    # hostname_string [40:80]: dotted IP padded
    ip_str = ip_addr.encode("ascii")
    entry[40 : 40 + len(ip_str)] = ip_str
    entry[40 + len(ip_str) : 80] = b" " * (40 - len(ip_str))
    # field3 [80:120]: '-' padded
    entry[80] = ord(b"-")
    entry[81:120] = b" " * 39
    # zeros [120:135]: all zero
    entry[120:135] = b"\x00" * 15
    # ffff marker [135:137]
    entry[135:137] = b"\xff\xff"
    # IP primary [137:141]
    ip_bytes = _socket.inet_aton(ip_addr)
    entry[137:141] = ip_bytes
    # IP secondary [141:145]: same
    entry[141:145] = ip_bytes
    # port [145:147]: BE uint16
    entry[145:147] = port.to_bytes(2, "big")
    # trailing [147:160]: zeros
    entry[147:160] = b"\x00" * 13

    body = bytes(header) + bytes(entry)
    # Fix the NI length prefix to match the new body size
    ni_len = (len(body) - 4).to_bytes(4, "big")
    return ni_len + body[4:]


# Wire-captured MS→CLIENT 114-byte login ack frame.
# Source: captures/phase03_msgserver_capture_output.txt line 30-37.
_MS_LOGIN_ACK = bytes.fromhex(
    "0000006e"  # NI length = 110 (total frame = 114)
    "2a2a4d455353414745"
    "2a2a"  # "**MESSAGE**"
    "00"
    "04"
    "00"
    "2d"  # key=0, version=4, pad=0, sender_type='-'
    + "20" * 39
    + "00"  # sender_name: 39 spaces + null = 40 bytes
    + "000000000000000000000000"  # zeros [59:71]
    + "000100"  # [71:74] [ASSUMED] direction byte
    + "000000000000000000000000"  # [74:86] zeros
    + "20" * 28  # spaces [86:114]
)


# Test 1: parsing a valid SAPMS server-list golden frame returns the expected
# per-server (host, port) entries (wire-confirmed: 192.168.88.7 on port 3200).
def test_parse_sapms_server_list_golden_frame() -> None:
    """parse_sapms_server_list returns 3 (host, port) entries from the golden
    598-byte frame: entry0=(192.168.99.6,0), entry1=(192.168.88.7,3200),
    entry2=(127.0.0.1,0). wire-captured: captures/phase03_msgserver_capture_output.txt."""
    frame = _golden_frame()
    entries = parse_sapms_server_list(frame)
    # There are 3 server entries in the golden frame.
    assert len(entries) == 3, f"expected 3 entries, got {len(entries)}"
    # Entry 0: inactive server 192.168.99.6 port 0
    host0, port0 = entries[0]
    assert host0 == "192.168.99.6", f"entry0 host: {host0!r}"
    assert port0 == 0, f"entry0 port: {port0}"
    # Entry 1: active server 192.168.88.7 port 3200 (the only non-zero port)
    host1, port1 = entries[1]
    assert host1 == "192.168.88.7", f"entry1 host: {host1!r}"
    assert port1 == 3200, f"entry1 port: {port1}"
    # Entry 2: loopback 127.0.0.1 port 0
    host2, port2 = entries[2]
    assert host2 == "127.0.0.1", f"entry2 host: {host2!r}"
    assert port2 == 0, f"entry2 port: {port2}"


# Test 2: truncated frame (payload shorter than declared entries) raises ValueError
# with a bounds message (T-04-MSDOS: bounds-check declared count vs actual buffer).
def test_parse_sapms_server_list_truncated_raises() -> None:
    """A frame truncated in the middle of entries raises ValueError with a bounds
    message, not IndexError or silent truncation. T-04-MSDOS mitigated."""
    full = _golden_frame()
    # Keep header (118 bytes) plus only 80 bytes of first entry — truncated mid-entry.
    truncated = full[: 118 + 80]
    with pytest.raises(ValueError, match=r"(?i)(bounds|truncat|short|entry|buffer)"):
        parse_sapms_server_list(truncated)


# Test 3: wrong magic raises ValueError naming the magic problem. A mis-routed TCP
# stream or rogue message-server should be caught before any entry parsing.
def test_parse_sapms_server_list_wrong_magic_raises() -> None:
    """A frame with wrong magic (not '**MESSAGE**') raises ValueError with diagnostic
    text. T-04-MSERR: error surfaced as ValueError for CommunicationError in 04-05."""
    full = bytearray(_golden_frame())
    # Corrupt the magic bytes (offset 4..14)
    full[4:15] = b"**INVALID**"
    with pytest.raises(ValueError, match=r"(?i)(magic|invalid|MESSAGE)"):
        parse_sapms_server_list(bytes(full))


# Test 4: resolve_full() uses parse_sapms_server_list and returns (ashost, sysnr)
# for the active server in the golden frame. T-04-REDIR: bounds validated.
# sysnr = (port - 3200) // 100 = 0 for port 3200.
def test_parse_sapms_resolve_full_uses_full_parser() -> None:
    """MessageServerClient.resolve_full uses parse_sapms_server_list and returns
    (ashost=192.168.88.7, sysnr=0) from the golden SAPMS exchange.

    MockTransport scripted with: [login_ack, server_list_response].
    resolve_full sends the login frame, reads login_ack, sends server-list request,
    reads server_list_response (golden 598-byte frame), parses it, and returns the
    least-loaded/first-active server. T-04-REDIR: bounds check applied.
    """
    golden_response = _golden_frame()
    transport = MockTransport([_MS_LOGIN_ACK, golden_response])
    client = MessageServerClient(transport)
    ashost, sysnr = client.resolve_full(group="PUBLIC", sysid="A4H")
    assert ashost == "192.168.88.7", f"ashost: {ashost!r}"
    assert sysnr == 0, f"sysnr: {sysnr}"


# Test 5 (T-04-REDIR): resolve_full rejects a server list where the only active
# entry has an out-of-range sysnr (port yields sysnr > 99).
def test_resolve_full_redir_bounds_rejects_bad_port() -> None:
    """resolve_full rejects a resolved redirect where sysnr is out of range.
    T-04-REDIR preserved: port 39321 -> sysnr = (39321-3200)//100 = 361 > 99."""
    bad_port = 39321  # sysnr = (39321 - 3200) // 100 = 361 -> rejected
    frame = _make_minimal_sapms_frame(ip_addr="192.168.1.1", port=bad_port)
    transport = MockTransport([_MS_LOGIN_ACK, frame])
    client = MessageServerClient(transport)
    with pytest.raises(ValueError, match=r"(?i)(redirect|redir|sysnr|port|range|bounds)"):
        client.resolve_full(group="PUBLIC", sysid="A4H")


# Test 6 (T-04-REDIR): resolve_full rejects a server list with all entries having
# IP 0.0.0.0 (invalid/empty host).
def test_resolve_full_redir_bounds_rejects_empty_host() -> None:
    """resolve_full raises ValueError when the selected server has IP 0.0.0.0.
    T-04-REDIR: host bounds check applied before returning."""
    frame = _make_minimal_sapms_frame(ip_addr="0.0.0.0", port=3200)
    transport = MockTransport([_MS_LOGIN_ACK, frame])
    client = MessageServerClient(transport)
    with pytest.raises(
        ValueError, match=r"(?i)(redirect|redir|host|empty|invalid|address|0\.0\.0\.0)"
    ):
        client.resolve_full(group="PUBLIC", sysid="A4H")
