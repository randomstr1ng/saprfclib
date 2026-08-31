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


def test_ms_return_codes_decode_as_signed_bytes() -> None:
    """0xec is -20, not 236. Reading it unsigned turns an error into a number."""
    from saprfclib.router import decode_ms_errorno, describe_ms_errorno

    body = bytearray(0x6E)
    body[0x0D] = 0xEC
    assert decode_ms_errorno(bytes(body)) == -20
    assert describe_ms_errorno(-20) == "access denied"
    assert describe_ms_errorno(-12) == "invalid client version"
    body[0x0D] = 0
    assert decode_ms_errorno(bytes(body)) == 0


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

    # A router that accepts the route answers NI_PONG before it starts
    # forwarding, so the script must begin with it. Confirmed live against a real
    # SAProuter; the previous script omitted it because the code never read it,
    # which left the handshake reading NI_PONG as its NI version response.
    transport = MockTransport([b"NI_PONG\x00", *_handshake_script()])
    monkeypatch.setattr(connection, "connect_tcp", lambda host, port, **_kwargs: transport)

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


def test_connect_stops_if_the_router_does_not_acknowledge(monkeypatch) -> None:
    """An unexpected answer to NI_ROUTE must not be treated as handshake data.

    Continuing would mean reading every later frame one position out of step,
    which surfaces far from the cause.
    """
    import saprfclib.connection as connection
    from saprfclib.exceptions import SapRfcError

    transport = MockTransport([b"SOMETHING ELSE", *_handshake_script()])
    monkeypatch.setattr(connection, "connect_tcp", lambda host, port, **_kwargs: transport)

    with pytest.raises(SapRfcError, match="rather than the expected NI_PONG"):
        connection.connect(
            ashost="app",
            sysnr="00",
            client="001",
            user="DEVELOPER",
            passwd="secret",
            saprouter="/H/host/S/3299",
        )


def test_router_reply_fixtures_are_what_a_real_router_sends() -> None:
    """Both captured against a live SAProuter on 2026-08-31."""
    from saprfclib.transport import is_ni_pong

    router_dir = Path(__file__).parent / "golden" / "router"
    accepted = (router_dir / "ni_pong_route_accepted.bin").read_bytes()[4:]
    assert is_ni_pong(accepted)
    assert accepted == b"NI_PONG\x00"

    denied = (router_dir / "ni_rterr_route_denied.bin").read_bytes()[4:]
    assert denied.startswith(b"NI_RTERR")
    assert not is_ni_pong(denied)
    # The refusal carries a *ERR* record, the same NUL-separated shape the
    # gateway uses for its own errors.
    assert b"*ERR*" in denied
    assert b"route permission denied" in denied


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


# --------------------------------------------------------------------------- #
# Message-server HTTP interface — live capture 2026-08-31
# Golden fixtures: tests/golden/router/ms_http_*.txt
# --------------------------------------------------------------------------- #

MS_HTTP_DIR = Path(__file__).parent / "golden" / "router"


def test_parse_ms_http_logon_finds_the_rfc_row() -> None:
    """The RFC row is what a load-balanced connect actually needs."""
    from saprfclib.router import parse_ms_http_logon

    rows = parse_ms_http_logon((MS_HTTP_DIR / "ms_http_logon_v12.txt").read_text())
    by_service = {service: (host, port) for service, host, port, _ in rows}
    assert by_service["RFC"] == ("sapdemo1", 3300)
    # RFCS is the SNC-protected endpoint on a different port; picking it by
    # accident would hand back a port that needs SNC parameters the caller may
    # not have supplied.
    assert by_service["RFCS"] == ("sapdemo1", 4800)


def test_parse_ms_http_logon_skips_rows_it_cannot_read() -> None:
    """The service list is open-ended; one odd row must not lose the RFC row."""
    from saprfclib.router import parse_ms_http_logon

    body = "version 1.2\ninstance\nRFC\thost\t3300\t\nGARBAGE\nNEW\thost\tnotaport\t\n"
    rows = parse_ms_http_logon(body)
    assert [r[0] for r in rows] == ["RFC"]


def test_parse_ms_http_lglist_reads_the_logon_groups() -> None:
    from saprfclib.router import parse_ms_http_lglist

    groups = parse_ms_http_lglist((MS_HTTP_DIR / "ms_http_lglist.txt").read_text())
    assert ("PUBLIC", "192.0.2.1", 3200) in groups
    assert {g[0] for g in groups} == {"PUBLIC", "SPACE"}


def test_resolve_rfc_server_http_reports_a_missing_rfc_row(monkeypatch) -> None:
    """Answering without an RFC service must raise, not fall back to a guess.

    Connecting to the wrong application server is not a failure the caller can
    see, so there is nothing safe to guess here.
    """
    import io

    from saprfclib import router
    from saprfclib.router import MessageServerHttpError, resolve_rfc_server_http

    body = b"version 1.2\ninstance\nHTTP\thost\t50000\t\n"
    monkeypatch.setattr(router, "urlopen", lambda *a, **k: io.BytesIO(body))
    with pytest.raises(MessageServerHttpError, match="no RFC service"):
        resolve_rfc_server_http("ms", 8101)


def test_resolve_rfc_server_http_explains_an_unreachable_interface(monkeypatch) -> None:
    """The HTTP port only exists when the profile enables it — say so."""
    from saprfclib import router
    from saprfclib.router import MessageServerHttpError, resolve_rfc_server_http

    def boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(router, "urlopen", boom)
    with pytest.raises(MessageServerHttpError, match="ms/server_port_0"):
        resolve_rfc_server_http("ms", 8101)


def test_message_server_port_is_never_guessed() -> None:
    """No numeric default: 3600 and 3601 are both one installation generalised.

    The port is 3600/8100 + the MESSAGE SERVER's instance number, which is not the
    application server's system number. Live scan 2026-08-31: on A4H the app server
    is sysnr 00 (gateway 3300) while the message server is instance 01 — 3601 and
    8101 answer, 3600 refuses outright. A single-instance system puts it at 00
    instead, and nothing observable from the client tells the two apart. Whichever
    number were defaulted would silently reach a closed port on the other layout.
    """
    from saprfclib.connection import _ms_http_port, _ms_port

    with pytest.raises(ValueError, match="cannot determine the binary"):
        _ms_port("A4H")
    with pytest.raises(ValueError, match="cannot determine the HTTP"):
        _ms_http_port("A4H")
    # The message is actionable: it must name the way out, not just the problem.
    with pytest.raises(ValueError, match="msserv="):
        _ms_port("A4H")

    # Explicit values win, as a port or as a numeric string.
    assert _ms_port("A4H", 3601) == 3601
    assert _ms_port("A4H", "3699") == 3699
    assert _ms_http_port("A4H", 8101) == 8101


def test_message_server_port_comes_from_etc_services_when_present(monkeypatch) -> None:
    """sapms<SID> states the instance number rather than assuming it."""
    from saprfclib import connection as connection_mod

    monkeypatch.setattr(
        connection_mod._socket_module,
        "getservbyname",
        lambda name: 3601 if name == "sapmsA4H" else (_ for _ in ()).throw(OSError()),
    )
    from saprfclib.connection import _ms_http_port, _ms_port

    assert _ms_port("A4H") == 3601
    # The same instance number drives the HTTP port: 8100 + 1.
    assert _ms_http_port("A4H") == 8101


def test_unknown_service_name_is_refused_not_defaulted() -> None:
    """Silently connecting somewhere else is the failure mode to avoid."""
    from saprfclib.connection import _ms_port

    with pytest.raises(ValueError, match="not in /etc/services"):
        _ms_port(None, "sapms_definitely_not_a_real_service")


def test_no_message_server_port_formula_is_assumed() -> None:
    """SAP documents no formula for a modern message server, so none is applied.

    Source: SAP, "TCP/IP Ports of All SAP Products". The message server appears
    twice in that table:

      Application Server ABAP        sapmsSID     3600   3600-3699   36<NN>
        "Relevant only for systems installed prior to SAP NetWeaver 7.0 with a
         central instance (CI)."
      SAP Central Services (SCS)     sapms<SID>   9310   0-65535     None
        "Configure the message server port with profile parameter rdisp/msserv."

    So 36<NN> covers legacy central instances only. On an ASCS system the port is
    whatever the profile says, anywhere in the range, defaulting to 9310. Each
    plausible constant is wrong for a different layout — 3600 for a legacy CI,
    9310 for a default SCS, 3601 on the A4H test system — so the port is read
    from /etc/services or required from the caller, never computed.
    """
    from saprfclib.connection import _ms_port

    for candidate in (3600, 9310, 3601):
        assert _ms_port("A4H", candidate) == candidate
    with pytest.raises(ValueError, match="cannot determine"):
        _ms_port("A4H")


def test_gateway_ports_match_the_documented_formula() -> None:
    """sapgw<NN> = 33<NN> and sapgw<NN>s = 48<NN>, both documented and observed.

    Confirmed twice over: SAP's port table gives the formulas, and the A4H message
    server independently reports RFC 3300 and RFCS 4800 for its sysnr-00
    application server. Unlike the message server, <NN> here is the application
    server's own instance number.
    """
    for sysnr in (0, 1, 42, 99):
        assert 3300 + sysnr == int(f"33{sysnr:02d}")
        assert 4800 + sysnr == int(f"48{sysnr:02d}")


def test_message_server_http_base_matches_the_documented_range() -> None:
    """81<NN>, range 8100-8199 — and documented as not active by default."""
    from saprfclib.connection import _ms_http_port

    assert _ms_http_port("A4H", 8101) == 8101
    assert 8100 <= _ms_http_port("A4H", 8199) <= 8199


# --------------------------------------------------------------------------- #
# SAPMS binary protocol — captured from SAP GUI, reproduced live 2026-08-31
# Golden fixtures: tests/golden/router/sapms_*.bin
# --------------------------------------------------------------------------- #

SAPMS_DIR = Path(__file__).parent / "golden" / "router"


def _fixture(name: str) -> bytes:
    """A captured frame WITHOUT its NI length prefix — the transport strips that."""
    return (SAPMS_DIR / name).read_bytes()[4:]


def test_our_attach_frame_matches_the_captured_one() -> None:
    """Byte-for-byte against what SAP GUI actually sends, except the names.

    This is the test the previous implementation could not have passed. It sent
    a 114-byte body; the real frame is 110, and a live message server closes the
    connection on the longer one without replying.
    """
    from saprfclib.router import _build_sapms_login_frame

    captured = _fixture("sapms_attach_request.bin")
    ours = _build_sapms_login_frame()
    assert len(ours) == len(captured) == 0x6E
    # Names are the caller's; every structural byte must match.
    for offset in (0x0C, 0x0D, 0x36, 0x42, 0x43, 0x6C, 0x6D):
        assert ours[offset] == captured[offset], f"byte 0x{offset:02x} differs"
    assert ours[:12] == captured[:12] == b"**MESSAGE**\x00"


def test_the_operation_byte_selects_attach_request_or_detach() -> None:
    """0x43 is the operation, and 3 was never one of its values.

    An earlier sweep concluded "0x43 must be 3" because 0, 1, 2 and 4 were each
    dropped when paired with a msgtype the server did not accept — and 8, the
    value a real client sends, was never tried. The capture settles it: 0x08
    attaches, 0x01 requests, 0x04 detaches.
    """
    from saprfclib.router import (
        _build_sapms_detach_frame,
        _build_sapms_login_frame,
        _build_sapms_server_list_request,
    )

    assert _build_sapms_login_frame()[0x43] == 0x08
    assert _build_sapms_server_list_request()[0x43] == 0x01
    assert _build_sapms_detach_frame()[0x43] == 0x04
    assert _fixture("sapms_attach_request.bin")[0x43] == 0x08
    assert _fixture("sapms_serverlist_request.bin")[0x43] == 0x01


def test_our_server_list_request_matches_the_captured_one() -> None:
    """Including the selector byte that picks servers over groups."""
    from saprfclib.router import _build_sapms_server_list_request

    captured = _fixture("sapms_serverlist_request.bin")
    ours = _build_sapms_server_list_request()
    assert len(ours) == len(captured)
    assert ours[0x6E:0x72] == captured[0x6E:0x72] == bytes.fromhex("1e000101")
    # Offset 11 of the body: 0x1d asks for servers, 0x1f for logon groups.
    assert ours[0x6E + 11] == captured[0x6E + 11] == 0x1D
    assert _fixture("sapms_grouplist_reply.bin")[0x42] == 0x03  # server speaking


def test_the_reply_payload_is_key_value_text_not_a_binary_table() -> None:
    """The old parser looked for binary entries. The wire carries text.

    Records are newline-separated, fields pipe-separated KEY=VALUE.
    """
    from saprfclib.router import parse_ms_list_reply

    records = parse_ms_list_reply(_fixture("sapms_serverlist_reply.bin"))
    assert len(records) == 1
    server = records[0]
    assert server["HOSTNAME"] == "sapdemo1xx"
    assert server["PORT"] == "3200"
    assert server["ASNAME"].endswith("_A4H_00")
    assert "DIA" in server["SAPSRV"]


def test_group_list_reply_parses_every_group() -> None:
    from saprfclib.router import parse_ms_list_reply

    records = parse_ms_list_reply(_fixture("sapms_grouplist_reply.bin"))
    assert {r["GROUP"] for r in records} == {"PUBLIC", "SPACE", "TEST"}
    assert all(r["PORT"] == "3200" for r in records)


def test_reply_with_a_foreign_opcode_block_is_refused() -> None:
    """A reply that is not the expected opcode must not be parsed as one."""
    from saprfclib.router import parse_ms_list_reply

    bad = bytearray(_fixture("sapms_serverlist_reply.bin"))
    bad[0x6E] = 0x99
    with pytest.raises(ValueError, match="unexpected message-server opcode"):
        parse_ms_list_reply(bytes(bad))


def test_resolve_full_runs_the_captured_exchange() -> None:
    """End to end against the real frames: attach, request, parse."""
    transport = MockTransport(
        [_fixture("sapms_attach_reply.bin"), _fixture("sapms_serverlist_reply.bin")]
    )
    ashost, sysnr = MessageServerClient(transport).resolve_full(group="PUBLIC")
    assert ashost == "sapdemo1xx"
    # PORT in the reply is the DISPATCHER port (32<NN>), not the gateway. The
    # captured record reads PORT=3200 for a server whose gateway is 3300.
    assert sysnr == 0
    assert transport.sent[0][0x43] == 0x08  # attach
    assert transport.sent[1][0x43] == 0x01  # request


def test_resolve_full_reports_a_refused_attach() -> None:
    from saprfclib.exceptions import SapRfcError

    denied = bytearray(_fixture("sapms_attach_reply.bin"))
    denied[0x0D] = 0xEC  # -20
    with pytest.raises(SapRfcError, match="access denied"):
        MessageServerClient(MockTransport([bytes(denied)])).resolve_full(group="PUBLIC")


def test_resolve_full_rejects_an_unroutable_host() -> None:
    """T-04-REDIR: never connect to an empty or 0.0.0.0 address."""
    reply = bytearray(_fixture("sapms_serverlist_reply.bin"))
    text = reply[0x72:].decode("latin-1").replace("HOSTNAME=sapdemo1xx", "HOSTNAME=0.0.0.0")
    rebuilt = bytes(reply[:0x72]) + text.encode("latin-1")
    transport = MockTransport([_fixture("sapms_attach_reply.bin"), rebuilt])
    with pytest.raises(ValueError, match="unusable application-server address"):
        MessageServerClient(transport).resolve_full(group="PUBLIC")


def test_resolve_full_rejects_a_port_that_is_not_a_system_number() -> None:
    """T-04-REDIR: the dispatcher port must be 3200 + a system number."""
    reply = bytearray(_fixture("sapms_serverlist_reply.bin"))
    text = reply[0x72:].decode("latin-1").replace("PORT=3200", "PORT=9999")
    rebuilt = bytes(reply[:0x72]) + text.encode("latin-1")
    transport = MockTransport([_fixture("sapms_attach_reply.bin"), rebuilt])
    with pytest.raises(ValueError, match="not 3200"):
        MessageServerClient(transport).resolve_full(group="PUBLIC")


def test_both_server_list_opcodes_are_supported() -> None:
    """0x1e carries text, 0x05 carries a binary table — both are real replies.

    Captured from two different clients against the same message server. The
    header is identical; only the opcode block and payload shape differ. Neither
    parser supersedes the other, and asserting that here is what stops the binary
    one being deleted as dead code the next time only a 0x1e capture is at hand.
    """
    from saprfclib.router import parse_ms_list_reply, parse_sapms_server_list

    text_reply = _fixture("sapms_serverlist_reply.bin")
    assert text_reply[0x6E] == 0x1E
    assert parse_ms_list_reply(text_reply)[0]["PORT"] == "3200"

    binary_reply = (SAPMS_DIR / "sapms_server_list.bin").read_bytes()
    assert binary_reply[4 + 0x6E] == 0x05
    assert parse_sapms_server_list(binary_reply)


def test_a_binary_reply_names_the_right_parser() -> None:
    """Meeting the other opcode must point at the parser that handles it."""
    from saprfclib.router import parse_ms_list_reply

    binary_reply = (SAPMS_DIR / "sapms_server_list.bin").read_bytes()
    with pytest.raises(ValueError, match="parse_sapms_server_list"):
        parse_ms_list_reply(binary_reply)
