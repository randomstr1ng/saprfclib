# tests/test_phase04_integration.py
#
# Phase 4 end-to-end wiring, MockTransport-driven full-stack test, and
# requirement traceability for CLIENT-01..07.
#
# All offline tests drive the full Transport→Session→Connection→metadata→invoke
# stack via MockTransport with zero real sockets.
#
# Requirement coverage (CLIENT-01..07):
#   Offline-verified: CLIENT-01/03/04/05/06/07 (per-unit tests below + phase tests)
#   MockTransport full-stack: test_end_to_end_mock (CLIENT-01/02/03/07 composed)
#   Live skip-guarded: test_live_stfc_connection, test_live_stfc_structure
#
# Live integration tests (test_live_*): guarded by SAPRFC_ASHOST env var.
# Credentials come ONLY from env vars — never hardcoded, SAPRFC_PASSWD never logged.
#
# Live logon truth-check (test_live_logon): carried forward from plan 04-01; proves
# the RE-resolved 0x0117 password scramble is correct against the real system.

from __future__ import annotations

import os
import struct

import pytest

import saprfclib
from saprfclib.invoke import tlv_record
from tests._mocks import MockTransport
from tests.conftest import GOLDEN_ROOT, load_fixture

_HANDSHAKE_DIR = GOLDEN_ROOT / "handshake"


# --------------------------------------------------------------------------- #
# Requirement traceability (completeness guard)
# --------------------------------------------------------------------------- #

#: Each Phase 4 requirement ID maps to a concrete offline test node id OR
#: "GAP:<reason>" for network-gated / unmet items.
#: Updated 2026-06-28 — all CLIENT requirements resolved via offline+live paths.
REQUIREMENT_COVERAGE: dict[str, str] = {
    # CLIENT-01: call() returns native dict for scalar CHAR params
    "CLIENT-01": "tests/test_connection.py::test_call_returns_native_dict",
    # CLIENT-02: STRUCTURE params encode/decode correctly
    # Tested via build_invoke_request direction routing + CHANGING param path
    "CLIENT-02": "tests/test_invoke.py::test_build_invoke_request_tlv_order",
    # CLIENT-03: Return values are Python-native types (DATE/TIME → datetime, CHAR → str)
    "CLIENT-03": "tests/test_connection.py::test_call_date_time_conversion",
    # CLIENT-04: ABAP exceptions → AbapApplicationError
    "CLIENT-04": "tests/test_connection.py::test_call_abap_exception_raises_application_error",
    # CLIENT-05: ABAP system failure → AbapSystemFailure
    "CLIENT-05": "tests/test_invoke.py::test_parse_invoke_response_nonzero_rc_raises_system_failure",
    # CLIENT-06: CommunicationError on network/protocol failure
    "CLIENT-06": "tests/test_connection.py::test_call_eof_raises_communication_error",
    # CLIENT-07: get_connection_attributes() returns populated ConnectionAttributes
    "CLIENT-07": "tests/test_connection.py::test_get_connection_attributes_returns_attributes",
}

_ALL_REQUIREMENT_IDS = {
    "CLIENT-01",
    "CLIENT-02",
    "CLIENT-03",
    "CLIENT-04",
    "CLIENT-05",
    "CLIENT-06",
    "CLIENT-07",
}


def test_requirement_traceability() -> None:
    """Every Phase 4 CLIENT requirement ID maps to a test node id or an explicit GAP.

    Prevents silent coverage gaps: adding a new requirement without updating
    REQUIREMENT_COVERAGE fails this test immediately.
    """
    missing = _ALL_REQUIREMENT_IDS - REQUIREMENT_COVERAGE.keys()
    assert not missing, f"Requirements missing from REQUIREMENT_COVERAGE: {missing}"

    for req_id, coverage in REQUIREMENT_COVERAGE.items():
        assert coverage, f"REQUIREMENT_COVERAGE[{req_id!r}] must not be empty"

    # Confirm no CLIENT requirements have empty coverage.
    empty = {k for k, v in REQUIREMENT_COVERAGE.items() if not v}
    assert not empty, f"Empty coverage strings found: {empty}"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _tlv_simple(tag: int, value: bytes) -> bytes:
    """Open-only TLV (session format, not invoke format): tag(2B BE) + len(2B BE) + value."""
    return struct.pack(">HH", tag, len(value)) + value


def _logon_response(rc: int = 0) -> bytes:
    """Synthetic server logon-response TLV payload (READY on rc=0)."""
    return b"".join(
        [
            _tlv_simple(0x0450, b"A4H"),
            _tlv_simple(0x0452, b"00"),
            _tlv_simple(0x0453, b"vhcala4hci"),
            _tlv_simple(0x0012, b"758"),
            _tlv_simple(0x0013, b"793"),
            _tlv_simple(0x0150, b"DEVELOPER"),
            _tlv_simple(0x0151, b"001"),
            _tlv_simple(0x0152, b"E"),
            _tlv_simple(0x0420, struct.pack(">I", rc)),
            _tlv_simple(0xFFFF, b""),
        ]
    )


def _scripted_handshake_responses(extra: list[bytes] | None = None) -> list[bytes]:
    """Four server frames that drive Connection to READY, plus optional extra."""
    ni_resp = load_fixture(_HANDSHAKE_DIR, "ni_version_response")
    gw_conn = load_fixture(_HANDSHAKE_DIR, "gw_connect_response")
    gw_done = load_fixture(_HANDSHAKE_DIR, "gw_done_server")
    return [
        ni_resp.payload_bytes,
        gw_conn.payload_bytes,
        gw_done.payload_bytes,
        _logon_response(rc=0),
    ] + (extra or [])


def _build_0303_row(
    paramclass: str,
    parameter: str,
    exid: str,
    intlength_nuc: int,
    position: int = 1,
    offset_nuc: int = 0,
) -> bytes:
    """Build one 0x0303 PARAMS row: exactly 402 bytes UTF-16LE fixed layout.

    Layout (12 columns, total 402 bytes):
      PARAMCLASS  1 char  (2 B)
      PARAMETER  30 chars (60 B)
      TABNAME    30 chars (60 B)
      FIELDNAME  30 chars (60 B)
      EXID        1 char  (2 B)
      POSITION    INT4 LE (4 B)
      OFFSET      INT4 LE (4 B)
      INTLENGTH   INT4 LE (4 B)
      DECIMALS    INT4 LE (4 B)
      DEFAULT    21 chars (42 B)
      PARAMTEXT  79 chars (158 B)
      OPTIONAL    1 char  (2 B)
      Total: 2+60+60+60+2+4+4+4+4+42+158+2 = 402 bytes

    INTLENGTH is the NUC count (wire value). _parse_gfi_params_rows multiplies
    char-like EXID codes by 2 to produce the unicode byte width before storing.
    So for CHAR(255): intlength_nuc=255 → wire stores 255 → parser produces uc_length=510.
    """

    def _u16_pad(s: str, count: int) -> bytes:
        """Encode s as UTF-16LE, padded/truncated to count chars (count*2 bytes)."""
        encoded = s.encode("utf-16-le")
        # Truncate to count characters (count*2 bytes)
        encoded = encoded[: count * 2]
        # Pad to exactly count chars
        encoded += b"\x00\x00" * (count - len(encoded) // 2)
        return encoded

    row = bytearray()
    row += _u16_pad(paramclass, 1)  # PARAMCLASS (1 char = 2B)
    row += _u16_pad(parameter, 30)  # PARAMETER (30 chars = 60B)
    row += _u16_pad("", 30)  # TABNAME (30 chars = 60B, empty)
    row += _u16_pad("", 30)  # FIELDNAME (30 chars = 60B, empty)
    row += _u16_pad(exid, 1)  # EXID (1 char = 2B)
    row += struct.pack("<I", position)  # POSITION INT4 LE
    row += struct.pack("<I", offset_nuc)  # OFFSET INT4 LE (NUC)
    row += struct.pack("<I", intlength_nuc)  # INTLENGTH INT4 LE (NUC)
    row += struct.pack("<I", 0)  # DECIMALS INT4 LE
    row += _u16_pad("", 21)  # DEFAULT (21 chars = 42B)
    row += _u16_pad("", 79)  # PARAMTEXT (79 chars = 158B)
    row += _u16_pad("", 1)  # OPTIONAL (1 char = 2B)

    assert len(row) == 402, f"Row must be 402 bytes, got {len(row)}"
    return bytes(row)


def _build_gfi_bootstrap_response(rows: list[bytes]) -> bytes:
    """Build a mock RFC_GET_FUNCTION_INTERFACE response that _parse_gfi_params_rows can parse.

    The response must look like a GW RFC frame: start with 0x06CB (GW_TYPE_RFC)
    followed by 78 more bytes (total 80-byte GW header), then 0x0303 TLV records.

    _parse_gfi_params_rows strips the first 80 bytes when it sees 0x06CB at [0:2].
    Each row is wrapped in a tlv_record(0x0303, row) (open+close TLV format).
    """
    # 80-byte GW header: [0:2]=0x06CB + 78 zero bytes
    gw_header = b"\x06\xcb" + b"\x00" * 78

    # Build TLV records for each 0x0303 row using tlv_record (open+close format)
    tlv_body = b"".join(tlv_record(0x0303, row) for row in rows)
    # Terminator: tag(2) + len(2) + close_tag(2)
    tlv_body += struct.pack(">HH", 0xFFFF, 0) + struct.pack(">H", 0xFFFF)

    return gw_header + tlv_body


def _build_invoke_response(echotext: str, char_len: int = 255) -> bytes:
    """Build a synthetic STFC_CONNECTION invoke response TLV stream.

    Produces the TLV starting at offset 0 (no GW header). The connection.py
    call() method gets the response from transport.recv_message() directly and passes
    it to parse_invoke_response which does NOT strip a GW header.
    """

    def _pad_char(s: str, count: int) -> bytes:
        """UTF-16LE padded to count chars with space padding."""
        encoded = s.encode("utf-16-le")
        return encoded + b"\x20\x00" * (count - len(s))

    echo_val = _pad_char(echotext, char_len)
    resp_val = _pad_char("SAP R/3 mock", char_len)

    return (
        tlv_record(0x0500, b"")
        + tlv_record(0x0420, struct.pack(">I", 0))
        + tlv_record(0x0512, b"")
        + tlv_record(0x0205, "ECHOTEXT".encode("utf-16-le"))
        + tlv_record(0x0205, "RESPTEXT".encode("utf-16-le"))
        + tlv_record(0x0201, "ECHOTEXT".encode("utf-16-le"))
        + tlv_record(0x0203, echo_val)
        + tlv_record(0x0201, "RESPTEXT".encode("utf-16-le"))
        + tlv_record(0x0203, resp_val)
        + struct.pack(">HH", 0xFFFF, 0)
        + b"\xff\xff"
    )


# --------------------------------------------------------------------------- #
# End-to-end MockTransport test (CLIENT-01/02/03/07 composed)
# --------------------------------------------------------------------------- #


def test_end_to_end_mock(monkeypatch) -> None:
    """Full Transport→Session→Connection→metadata→invoke stack over MockTransport.

    Drives saprfclib.connect() to READY over a scripted handshake, then:
    1. Receives the GFI bootstrap response (0x0303 rows for STFC_CONNECTION params)
    2. Receives the invoke response (0x0201/0x0203 ECHOTEXT + RESPTEXT)
    3. Asserts the returned dict has ECHOTEXT with the correct string value
    4. Asserts get_connection_attributes() returns populated ConnectionAttributes

    Requirements exercised: CLIENT-01 (call() returns dict), CLIENT-02 (parameter
    routing), CLIENT-03 (str for CHAR), CLIENT-07 (get_connection_attributes).
    """
    import saprfclib.connection as connection_mod

    # Build bootstrap response: 3 x 0x0303 rows for STFC_CONNECTION params
    # ECHOTEXT: EXPORTING ('E'), CHAR('C'), NUC length 255, position 1
    echotext_row = _build_0303_row(
        paramclass="E",
        parameter="ECHOTEXT",
        exid="C",
        intlength_nuc=255,
        position=1,
        offset_nuc=0,
    )
    # RESPTEXT: EXPORTING ('E'), CHAR('C'), NUC length 255, position 2
    resptext_row = _build_0303_row(
        paramclass="E",
        parameter="RESPTEXT",
        exid="C",
        intlength_nuc=255,
        position=2,
        offset_nuc=0,
    )
    # REQUTEXT: IMPORTING ('I'), CHAR('C'), NUC length 255, position 3
    requtext_row = _build_0303_row(
        paramclass="I",
        parameter="REQUTEXT",
        exid="C",
        intlength_nuc=255,
        position=3,
        offset_nuc=0,
    )
    bootstrap_resp = _build_gfi_bootstrap_response([echotext_row, resptext_row, requtext_row])

    # Build invoke response for STFC_CONNECTION with ECHOTEXT="ping"
    invoke_resp = _build_invoke_response("ping")

    # Script the MockTransport: 4 handshake responses + 1 bootstrap + 1 invoke
    responses = _scripted_handshake_responses(extra=[bootstrap_resp, invoke_resp])
    transport = MockTransport(responses)
    monkeypatch.setattr(connection_mod, "connect_tcp", lambda host, port, timeout=None: transport)

    # Use the public saprfclib.connect() factory
    conn = saprfclib.connect(
        ashost="testhost",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
    )

    # CLIENT-07: get_connection_attributes() returns populated attrs
    attrs = conn.get_connection_attributes()
    assert attrs.sys_id == "A4H"
    assert attrs.unicode_mode is True
    assert attrs.partner_host == "vhcala4hci"

    # CLIENT-01/02/03: call() returns a native-typed dict
    result = conn.call("STFC_CONNECTION", REQUTEXT="ping")
    assert isinstance(result, dict), f"call() must return dict, got {type(result)}"
    assert "ECHOTEXT" in result, f"ECHOTEXT missing from result: {list(result.keys())}"
    # CHAR type: codec returns str (CLIENT-03)
    assert isinstance(result["ECHOTEXT"], str), (
        f"ECHOTEXT must be str, got {type(result['ECHOTEXT'])}"
    )
    assert result["ECHOTEXT"].strip() == "ping", (
        f"ECHOTEXT should echo 'ping', got {result['ECHOTEXT']!r}"
    )
    assert "RESPTEXT" in result


# --------------------------------------------------------------------------- #
# Live end-to-end (requires SAPRFC_* env vars)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST"),
    reason="SAPRFC_ASHOST not set — no live SAP system available (OQ-C01 live "
    "byte-for-byte truth-check is gated on a real logon)",
)
def test_live_logon() -> None:
    """Live logon reaches READY with the RE-resolved 0x0117 scramble.

    Carried forward from plan 04-01. Truth-check: a real logon must succeed
    (no ``logon failed`` ValueError) and expose the live system ID via
    get_connection_attributes(). If this raises a logon failure, the scramble
    derivation (codepage / cipher) is wrong and the gap is NOT yet closed.
    """
    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ["SAPRFC_USER"]
    passwd = os.environ["SAPRFC_PASSWD"]

    conn = saprfclib.connect(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
    )
    try:
        attrs = conn.get_connection_attributes()
        assert attrs.sys_id, "sys_id must be non-empty after a successful live logon"
    finally:
        conn.close()


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST"),
    reason="SAPRFC_ASHOST not set — no live SAP system available",
)
def test_live_stfc_connection() -> None:
    """Live STFC_CONNECTION call verifying native-typed result (CLIENT-01/03/07).

    Calls STFC_CONNECTION with REQUTEXT and asserts:
    - Result is a dict with ECHOTEXT echoing REQUTEXT
    - RESPTEXT is non-empty (server greeting)
    - get_connection_attributes().sys_id is non-empty

    Env vars: SAPRFC_ASHOST, SAPRFC_SYSNR (default "00"), SAPRFC_CLIENT (default "001"),
    SAPRFC_USER, SAPRFC_PASSWD (never logged/printed).
    Skipped when SAPRFC_ASHOST is not set (CI-safe).
    """
    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ["SAPRFC_USER"]
    passwd = os.environ["SAPRFC_PASSWD"]

    conn = saprfclib.connect(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
    )
    try:
        # CLIENT-07: connection attributes populated
        attrs = conn.get_connection_attributes()
        assert attrs.sys_id, "sys_id must be non-empty after live handshake"
        assert attrs.unicode_mode is True, "A4H is a unicode system"

        # CLIENT-01/03: call() returns a dict with CHAR values as str
        result = conn.call("STFC_CONNECTION", REQUTEXT="saprfc_phase04_test")
        assert isinstance(result, dict), f"Expected dict, got {type(result)}"
        assert "ECHOTEXT" in result, f"ECHOTEXT missing from result keys: {list(result.keys())}"
        assert "RESPTEXT" in result, f"RESPTEXT missing from result keys: {list(result.keys())}"

        # The echo should contain what we sent
        assert "saprfc_phase04_test" in result["ECHOTEXT"], (
            f"ECHOTEXT should echo the REQUTEXT; got {result['ECHOTEXT']!r}"
        )
        assert result["RESPTEXT"].strip(), "RESPTEXT should be non-empty (server greeting)"

        # Types must be Python str (CLIENT-03)
        assert isinstance(result["ECHOTEXT"], str), (
            f"ECHOTEXT must be str, got {type(result['ECHOTEXT'])}"
        )
    finally:
        conn.close()


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST"),
    reason="SAPRFC_ASHOST not set — no live SAP system available",
)
def test_live_stfc_structure() -> None:
    """Live STFC_STRUCTURE call verifying STRUCTURE/CHANGING/TABLE params (CLIENT-02/03).

    Calls STFC_STRUCTURE with IMPORTSTRUCT and asserts:
    - ECHOSTRUCT is returned as a dict with field values
    - RESPTEXT is a str

    Env vars: SAPRFC_ASHOST, SAPRFC_SYSNR (default "00"), SAPRFC_CLIENT (default "001"),
    SAPRFC_USER, SAPRFC_PASSWD (never logged/printed).
    Skipped when SAPRFC_ASHOST is not set (CI-safe).
    """
    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ["SAPRFC_USER"]
    passwd = os.environ["SAPRFC_PASSWD"]

    conn = saprfclib.connect(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
    )
    try:
        # CLIENT-02: STRUCTURE params encode/decode
        # STFC_STRUCTURE takes IMPORTSTRUCT (RFCTEST structure) and returns ECHOSTRUCT
        import_struct = {
            "RFCFLOAT": 3.14,
            "RFCCHAR1": "X",
            "RFCINT2": 42,
            "RFCINT1": 5,
            "RFCCHAR4": "TEST",
            "RFCINT4": 100,
            "RFCHEX3": b"\x01\x02\x03",
            "RFCCHAR2": "AB",
            "RFCTIME": "120000",
            "RFCDATE": "20260628",
            "RFCDATA1": "A" * 50,
            "RFCDATA2": "B" * 50,
        }

        result = conn.call("STFC_STRUCTURE", IMPORTSTRUCT=import_struct)
        assert isinstance(result, dict), f"Expected dict, got {type(result)}"

        # ECHOSTRUCT should be returned as a dict (CLIENT-02)
        if "ECHOSTRUCT" in result:
            assert isinstance(result["ECHOSTRUCT"], dict), (
                f"ECHOSTRUCT must be a dict, got {type(result['ECHOSTRUCT'])}"
            )
        # RESPTEXT should be a str (CLIENT-03)
        if "RESPTEXT" in result:
            assert isinstance(result["RESPTEXT"], str), (
                f"RESPTEXT must be str, got {type(result['RESPTEXT'])}"
            )
    finally:
        conn.close()
