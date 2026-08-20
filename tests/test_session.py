# tests/test_session.py
#
# Golden-fixture-driven tests for the sans-I/O RFC Session state machine
# (Plan 03-02). Drives the documented direct-TCP handshake with ZERO sockets:
# Session.start() emits the NI-version request payload; Session.feed(server_bytes)
# walks DISCONNECTED → CONNECTED → NI_VERSIONED → GW_CONNECTED → LOGGED_IN → READY.
#
# The real captured NI / GW frames come from tests/golden/handshake/ and are
# compared byte-for-byte (skipping variable-annotated fields) via compare_bytes.
#
# [ASSUMED] The server logon-response (frame 15) is NOT yet extracted as a
# standalone golden fixture (handshake.md line 212). The `_logon_response` helper
# below synthesizes a minimal TLV stream from the response tags documented in
# handshake.md lines 188-205. This synthetic payload defines the contract the
# GREEN Session._parse_tlv parser consumes; it is NEVER compared byte-for-byte
# with compare_bytes (only the real captured NI/GW fixtures are).

import struct

import pytest

from saprfclib.session import ConnectionAttributes, Session, SessionState
from tests.conftest import GOLDEN_ROOT, compare_bytes, load_fixture

HANDSHAKE_DIR = GOLDEN_ROOT / "handshake"


# --------------------------------------------------------------------------- #
# Synthetic logon-response TLV builder ([ASSUMED] shape — see module comment).
#
# TLV record shape (the contract GREEN must parse):
#   tag    2B  big-endian uint16
#   length 2B  big-endian uint16 (byte length of value)
#   value  <length> bytes
# Stream terminates with the 0xFFFF tag (zero-length).
# --------------------------------------------------------------------------- #
def _tlv(tag: int, value: bytes) -> bytes:
    return struct.pack(">HH", tag, len(value)) + value


def _logon_response(rc: int = 0) -> bytes:
    """Build a synthetic server logon-response TLV payload (frame 15).

    RE truth (Task 3 live capture): error is signaled by presence of tag 0x0402
    (error message text).  On success, 0x0402 is absent.  Tag 0x0420 does NOT
    appear in live logon-response captures — it is RFCPING-specific.
    """
    parts: list[bytes] = [
        _tlv(0x0450, b"A4H"),  # SAP System ID
        _tlv(0x0452, b"00"),  # System number
        _tlv(0x0453, b"vhcala4hci"),  # Application server host
        _tlv(0x0012, b"758"),  # SAP release
        _tlv(0x0013, b"793"),  # Kernel version
        _tlv(0x0150, b"DEVELOPER"),  # Logged-in user
        _tlv(0x0151, b"001"),  # Client
        _tlv(0x0152, b"E"),  # Language
    ]
    if rc != 0:
        parts.append(_tlv(0x0402, f"logon error rc={rc}".encode()))  # error text
    parts.append(_tlv(0xFFFF, b""))  # Terminator
    return b"".join(parts)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_start_emits_ni_version_request() -> None:
    """start() returns the NI-version request payload matching the golden fixture
    on all non-variable bytes."""
    fix = load_fixture(HANDSHAKE_DIR, "ni_version_request")
    sess = Session()
    payload = sess.start()
    assert sess.state is SessionState.CONNECTED
    assert compare_bytes(payload, fix.payload_bytes, fix.field_annotations) == []


def test_feed_ni_version_response_transitions() -> None:
    """After start(), feeding the NI-version response moves CONNECTED →
    NI_VERSIONED and records negotiated codepage '4103'."""
    resp = load_fixture(HANDSHAKE_DIR, "ni_version_response")
    sess = Session()
    sess.start()
    sess.feed(resp.payload_bytes)
    assert sess.state is SessionState.NI_VERSIONED


def test_full_handshake_reaches_ready() -> None:
    """Driving start() then feeding ni_version_response, gw_connect_response,
    gw_done_server, then a synthetic logon-response with rc=0 reaches READY."""
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response")
    gw_conn = load_fixture(HANDSHAKE_DIR, "gw_connect_response")
    gw_done = load_fixture(HANDSHAKE_DIR, "gw_done_server")

    sess = Session()
    sess.start()
    sess.feed(ni_resp.payload_bytes)
    sess.feed(gw_conn.payload_bytes)
    sess.feed(gw_done.payload_bytes)
    sess.feed(_logon_response(rc=0))
    assert sess.state is SessionState.READY


def test_attributes_after_handshake() -> None:
    """After READY, session.attributes is a ConnectionAttributes derived from the
    NI codepage and the logon-response TLV tags."""
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response")
    gw_conn = load_fixture(HANDSHAKE_DIR, "gw_connect_response")
    gw_done = load_fixture(HANDSHAKE_DIR, "gw_done_server")

    sess = Session()
    sess.start()
    sess.feed(ni_resp.payload_bytes)
    sess.feed(gw_conn.payload_bytes)
    sess.feed(gw_done.payload_bytes)
    sess.feed(_logon_response(rc=0))

    attrs = sess.attributes
    assert isinstance(attrs, ConnectionAttributes)
    assert attrs.codepage == "4103"
    assert attrs.unicode_mode is True
    assert attrs.sys_id == "A4H"
    assert attrs.user == "DEVELOPER"
    assert attrs.client == "001"
    assert attrs.language == "E"
    assert attrs.partner_rel == "758"


def test_logon_failure_nonzero_rc_raises() -> None:
    """A logon-response containing tag 0x0402 (error text) raises ValueError
    'logon failed' and does NOT reach READY."""
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response")
    gw_conn = load_fixture(HANDSHAKE_DIR, "gw_connect_response")
    gw_done = load_fixture(HANDSHAKE_DIR, "gw_done_server")

    sess = Session()
    sess.start()
    sess.feed(ni_resp.payload_bytes)
    sess.feed(gw_conn.payload_bytes)
    sess.feed(gw_done.payload_bytes)
    with pytest.raises(ValueError, match="logon failed"):
        sess.feed(_logon_response(rc=2))
    assert sess.state is not SessionState.READY


def test_feed_before_start_raises() -> None:
    """Feeding before start() (state DISCONNECTED) raises ValueError mentioning
    state."""
    sess = Session()
    with pytest.raises(ValueError, match="state"):
        sess.feed(b"\x00" * 68)


def test_require_state_rejects_wrong_state() -> None:
    """The in-flight guard rejects a non-READY state (CPIC single-conversation
    guard, TRANS-04)."""
    sess = Session()  # DISCONNECTED
    with pytest.raises(ValueError):
        sess._require_state(SessionState.READY)
