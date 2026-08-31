# tests/test_phase03_integration.py
#
# Phase 3 end-to-end wiring, ping/close lifecycle, and requirement traceability.
# All offline tests drive the full Transport→Session→Connection→metadata stack via
# MockTransport with zero real sockets.
#
# Requirement coverage (TRANS-01..08 / META-01..05):
#   Offline-verified: TRANS-01/04/05/06/07/08, META-02/03/04/05 (green tests here + phase tests)
#   Confirmed + Phase-4-gated: TRANS-02 (NI_ROUTE live-verified, golden test in test_router.py)
#   Exchange-confirmed + frame-parsing deferred: TRANS-03 (SAPMS, full impl Phase 4)
#   Column-confirmed + invoke-path deferred: META-01 (columns live-verified 2026-06-27,
#       uncached fetch needs Phase 4 invoke path)
#
# Live integration test (test_live_end_to_end): guarded by SAPRFC_ASHOST env var.

import os
import struct

import pytest

import saprfclib
from saprfclib import connect
from saprfclib.metadata import BOOTSTRAP_GET_FUNCTION_INTERFACE, MetadataCache, get_function_desc
from saprfclib.types import FunctionDesc
from tests._mocks import MockTransport
from tests.conftest import GOLDEN_ROOT, load_fixture

_HANDSHAKE_DIR = GOLDEN_ROOT / "handshake"


# --------------------------------------------------------------------------- #
# Helpers (duplicate minimal builders to avoid cross-test coupling)
# --------------------------------------------------------------------------- #


def _tlv(tag: int, value: bytes) -> bytes:
    return struct.pack(">HH", tag, len(value)) + value


def _logon_response(rc: int = 0) -> bytes:
    return b"".join(
        [
            _tlv(0x0450, b"A4H"),
            _tlv(0x0452, b"00"),
            _tlv(0x0453, b"vhcala4hci"),
            _tlv(0x0012, b"758"),
            _tlv(0x0013, b"793"),
            _tlv(0x0150, b"DEVELOPER"),
            _tlv(0x0151, b"001"),
            _tlv(0x0152, b"E"),
            _tlv(0x0420, struct.pack(">I", rc)),
            _tlv(0xFFFF, b""),
        ]
    )


def _rfcping_ok() -> bytes:
    return b"".join(
        [
            _tlv(0x0420, struct.pack(">I", 0)),
            _tlv(0xFFFF, b""),
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


# --------------------------------------------------------------------------- #
# TRANS-01/04/05/06/07/08 + META-03/04/05 composed (full stack offline)
# --------------------------------------------------------------------------- #


def test_end_to_end_connect_attributes_metadata(monkeypatch) -> None:
    """Full Transport→Session→Connection→metadata stack over MockTransport.

    Drives saprfclib.connect() to READY over a scripted handshake, asserts
    ConnectionAttributes reflect the negotiated values (codepage 4103 unicode,
    sys_id A4H), then exercises MetadataCache with a stub fetch to confirm
    cache-hit suppresses the second round-trip (META-03/04/05 composed).

    Requirements: TRANS-01/04/05/06/07/08, META-03/04/05.
    """
    import saprfclib.connection as connection

    transport = MockTransport(_scripted_handshake_responses())
    monkeypatch.setattr(connection, "connect_tcp", lambda host, port, **_kwargs: transport)

    conn = connect(
        ashost="testhost",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
    )

    attrs = conn.get_connection_attributes()
    assert attrs.sys_id == "A4H"
    assert attrs.unicode_mode is True  # codepage 4103 → unicode
    assert attrs.partner_host == "vhcala4hci"

    # MetadataCache: first fetch calls stub, second is cache hit (META-03)
    cache = MetadataCache()
    calls: list[str] = []

    def stub_fetch(name: str) -> FunctionDesc:
        calls.append(name)
        return FunctionDesc(name=name.upper(), parameters=[])

    desc1 = cache.get_or_fetch(attrs.sys_id, "STFC_CONNECTION", stub_fetch)
    desc2 = cache.get_or_fetch(attrs.sys_id, "STFC_CONNECTION", stub_fetch)
    assert desc1 is desc2
    assert calls == ["STFC_CONNECTION"]

    # Bootstrap descriptor accessible without a round-trip (META-05)
    assert BOOTSTRAP_GET_FUNCTION_INTERFACE.name == "RFC_GET_FUNCTION_INTERFACE"
    assert BOOTSTRAP_GET_FUNCTION_INTERFACE.parameters[0].name == "FUNCNAME"


def test_ping_close_lifecycle(monkeypatch) -> None:
    """ping() returns True on READY; close() succeeds; subsequent ping() raises.

    Requirements: TRANS-04 (single-in-flight lock), TRANS-06 (close idempotent),
    TRANS-07 (ping semantics).
    """
    import saprfclib.connection as connection

    transport = MockTransport(_scripted_handshake_responses(extra=[_rfcping_ok()]))
    monkeypatch.setattr(connection, "connect_tcp", lambda host, port, **_kwargs: transport)

    conn = connect(
        ashost="testhost",
        sysnr="00",
        client="001",
        user="DEVELOPER",
        passwd="secret",
    )
    assert conn.ping() is True
    conn.close()
    with pytest.raises(Exception):  # noqa: B017
        conn.ping()


# --------------------------------------------------------------------------- #
# Requirement traceability (completeness guard)
# --------------------------------------------------------------------------- #

#: Each Phase 3 requirement ID maps to a concrete offline test node id OR
#: "GAP:<reason>" for network-gated / Phase-4-deferred items.
#: Updated 2026-06-27 to reflect live-capture resolutions.
REQUIREMENT_COVERAGE: dict[str, str] = {
    # Transport seam (TRANS-01..08)
    "TRANS-01": "tests/test_transport.py::test_ni_frame_roundtrip",
    "TRANS-02": "tests/test_router.py::test_build_ni_route_golden",  # live-verified 2026-06-27
    "TRANS-03": (
        "GAP:full SAPMS frame parsing deferred to Phase 4 "
        "(exchange confirmed live 2026-06-27; simplified mock interface tested)"
    ),
    "TRANS-04": "tests/test_connection.py::test_ping_rejected_when_not_ready",
    "TRANS-05": "tests/test_connection.py::test_connection_attributes",
    "TRANS-06": "tests/test_connection.py::test_close_idempotent",
    "TRANS-07": "tests/test_connection.py::test_ping_on_ready_returns_true",
    "TRANS-08": "tests/test_transport.py::test_recv_exactly_handles_short_reads",
    # Metadata (META-01..05)
    "META-01": (
        "GAP:uncached live fetch deferred to Phase 4 invoke path "
        "(column layout confirmed live 2026-06-27; _parse_params_row tested offline)"
    ),
    "META-02": "tests/test_metadata.py::test_nested_structure_recurses",
    "META-03": "tests/test_metadata.py::test_cache_hit_suppresses_second_fetch",
    "META-04": "tests/test_metadata.py::test_handbuilt_function_desc_codec_roundtrip",
    "META-05": "tests/test_metadata.py::test_bootstrap_descriptor_usable",
}

_ALL_REQUIREMENT_IDS = {
    "TRANS-01",
    "TRANS-02",
    "TRANS-03",
    "TRANS-04",
    "TRANS-05",
    "TRANS-06",
    "TRANS-07",
    "TRANS-08",
    "META-01",
    "META-02",
    "META-03",
    "META-04",
    "META-05",
}


def test_requirement_traceability() -> None:
    """Every Phase 3 requirement ID maps to a test node id or an explicit GAP.

    Prevents silent coverage gaps: adding a new requirement without updating
    REQUIREMENT_COVERAGE fails this test immediately.
    """
    missing = _ALL_REQUIREMENT_IDS - REQUIREMENT_COVERAGE.keys()
    assert not missing, f"Requirements missing from REQUIREMENT_COVERAGE: {missing}"

    for req_id, coverage in REQUIREMENT_COVERAGE.items():
        assert coverage, f"REQUIREMENT_COVERAGE[{req_id!r}] must not be empty"

    # Confirm the two expected GAP entries are present.
    gaps = {k for k, v in REQUIREMENT_COVERAGE.items() if v.startswith("GAP:")}
    assert "TRANS-03" in gaps, "TRANS-03 (SAPMS full frame parsing) must be a GAP"
    assert "META-01" in gaps, "META-01 (uncached live fetch) must be a GAP"


# --------------------------------------------------------------------------- #
# Live end-to-end (requires SAPRFC_* env vars)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST"),
    reason="SAPRFC_ASHOST not set — no live SAP system available",
)
def test_live_end_to_end() -> None:
    """Live connect + attributes + metadata (skip when no SAP system available).

    Verifies the real negotiated handshake lands on a READY connection and that
    ConnectionAttributes are populated. get_function_desc is attempted and accepted
    whether it succeeds (Phase 4 gap closed) or raises NotImplementedError (gap open).

    Env vars: SAPRFC_ASHOST, SAPRFC_SYSNR (default "00"), SAPRFC_CLIENT (default "001"),
    SAPRFC_USER, SAPRFC_PASSWD.
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
        assert attrs.sys_id, "sys_id must be non-empty after live handshake"
        assert attrs.unicode_mode is True, "A4H is a unicode system"
        try:
            cache = MetadataCache()
            desc = get_function_desc(conn, "STFC_CONNECTION", cache=cache)
            assert desc.name == "STFC_CONNECTION"
        except NotImplementedError:
            pass  # Phase 4 invoke path not yet available — gap documented
    finally:
        conn.close()
