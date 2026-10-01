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


def _logon_response(rc: int = 0, *, with_sys_id: bool = True) -> bytes:
    """Build a synthetic server logon-response TLV payload (frame 15).

    Wire truth (live captures): a successful logon carries tag 0x0420 (RETURN_CODE,
    written by the dispatcher once it has run the embedded RFCPING) and no 0x0402; a
    plain authentication failure carries 0x0402 (error text) and no 0x0420. 0x0420's
    presence -- not 0x0450 -- is what marks a completed logon (D-38): NetWeaver 7.52
    omits 0x0450 even on success.

    ``with_sys_id`` controls tag 0x0450 (the SAP system id). Kernel 793 sends it;
    7.52 does not. It is kept here only to exercise attribute decoding, never the
    success/failure decision.
    """
    parts: list[bytes] = []
    if with_sys_id:
        parts.append(_tlv(0x0450, b"A4H"))  # SAP System ID (793 sends it; 7.52 omits)
    parts += [
        _tlv(0x0452, b"00"),  # System number
        _tlv(0x0453, b"vhcala4hci"),  # Application server host
        _tlv(0x0012, b"758"),  # SAP release
        _tlv(0x0013, b"793"),  # Kernel version
        _tlv(0x0150, b"DEVELOPER"),  # Logged-in user
        _tlv(0x0151, b"001"),  # Client
        _tlv(0x0152, b"E"),  # Language
    ]
    if rc != 0:
        # Plain auth rejection: error text, no return code (the dispatcher never ran).
        parts.append(_tlv(0x0402, f"logon error rc={rc}".encode()))
    else:
        # Completed logon: the dispatcher ran the embedded call and set 0x0420.
        parts.append(_tlv(0x0420, struct.pack(">I", 0)))
    parts.append(_tlv(0xFFFF, b""))  # Terminator
    return b"".join(parts)


def _authz_denied_logon_response(*, with_sys_id: bool = True) -> bytes:
    """A logon reply that AUTHENTICATED but whose embedded RFCPING was S_RFC-denied.

    Byte-shaped after live captures (issue #38): the completed logon carries tag
    0x0420 (RETURN_CODE, written once the dispatcher ran the RFCPING) alongside the
    ABAP exception tags — 0x0417 message number, 0x0403 exception key
    RFC_NO_AUTHORITY, 0x0415/0x0416 message class/type, and 0x0402 the message text.

    ``with_sys_id`` toggles tag 0x0450. Kernel 793 includes it; NetWeaver 7.52 omits
    it even here, which is exactly the shape that broke the old 0x0450-based rule
    (D-38). 0x0420 marks the completed logon in both shapes.
    """
    parts: list[bytes] = []
    if with_sys_id:
        parts.append(_tlv(0x0450, b"A4H"))  # 793 sends it; 7.52 omits it
    parts += [
        _tlv(0x0452, b"00"),
        _tlv(0x0453, b"vhcala4hci"),
        _tlv(0x0012, b"758"),
        _tlv(0x0013, b"793"),
        _tlv(0x0420, struct.pack(">I", 0)),  # return code present -> logon completed
        _tlv(0x0415, b"00"),  # message class
        _tlv(0x0416, b"X"),  # message type
        _tlv(0x0417, b"341"),  # message number (also the exception marker)
        _tlv(0x0403, b"RFC_NO_AUTHORITY"),  # exception key
        _tlv(0x0402, b"No RFC authorization for function module RFCPING."),
        _tlv(0xFFFF, b""),
    ]
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


def _drive_to_logon(sess: Session) -> None:
    ni_resp = load_fixture(HANDSHAKE_DIR, "ni_version_response")
    gw_conn = load_fixture(HANDSHAKE_DIR, "gw_connect_response")
    gw_done = load_fixture(HANDSHAKE_DIR, "gw_done_server")
    sess.start()
    sess.feed(ni_resp.payload_bytes)
    sess.feed(gw_conn.payload_bytes)
    sess.feed(gw_done.payload_bytes)


def test_authentication_failure_raises_logon_failed() -> None:
    """An error text (0x0402) with no return code (0x0420) is a real auth failure.

    No 0x0420 means the dispatcher never ran the embedded call, i.e. the logon did
    not authenticate. With only a bare message and no structured exception, this is a
    plain credential rejection and surfaces as "logon failed".
    """
    sess = Session()
    _drive_to_logon(sess)
    with pytest.raises(ValueError, match="logon failed"):
        sess.feed(_logon_response(rc=2, with_sys_id=False))
    assert sess.state is not SessionState.READY


def test_authz_denied_rfcping_raises_rfc_no_authority_not_logon_failed() -> None:
    """Auth OK (0x0450 present) but embedded RFCPING S_RFC-denied → the ABAP exception.

    Issue #38: this must NOT be reported as a generic 'logon failed'. It is a
    function-authorization denial; the reference client (pyrfc) raises the ABAP
    exception RFC_NO_AUTHORITY here, and so do we — with its real key and text,
    not a garbled message. Verified against a live capture on kernel 793.
    """
    from saprfclib.exceptions import AbapApplicationError

    sess = Session()
    _drive_to_logon(sess)
    with pytest.raises(AbapApplicationError) as ei:
        sess.feed(_authz_denied_logon_response())
    exc = ei.value
    assert exc.key == "RFC_NO_AUTHORITY"
    assert exc.message == "No RFC authorization for function module RFCPING."
    assert exc.msg_class == "00" and exc.msg_type == "X" and exc.msg_number == "341"
    assert sess.state is not SessionState.READY


def test_allow_restricted_logon_opens_despite_authz_denial() -> None:
    """With allow_restricted_logon, an S_RFC-denied RFCPING yields a usable session.

    Issue #38: a security tool enumerating low-privilege destinations wants the
    connection opened so it can make its own authorized calls. The reply carries
    the full attributes and the byte stream is in sync, so the session reaches
    READY and its attributes are populated.
    """
    sess = Session(allow_restricted_logon=True)
    _drive_to_logon(sess)
    sess.feed(_authz_denied_logon_response())
    assert sess.state is SessionState.READY
    assert sess.attributes is not None
    assert sess.attributes.sys_id == "A4H"


def test_authz_denied_without_sys_id_still_classified() -> None:
    """NetWeaver 7.52 omits 0x0450 even on an authenticated-but-denied reply.

    Issue #38 / D-38: classification must not depend on 0x0450. A reply that carries
    0x0420 (logon completed) plus the RFC_NO_AUTHORITY exception tags but NO 0x0450 --
    the live 7.52 shape -- must still raise the real ABAP exception by default, not a
    generic "logon failed".
    """
    from saprfclib.exceptions import AbapApplicationError

    sess = Session()
    _drive_to_logon(sess)
    with pytest.raises(AbapApplicationError) as ei:
        sess.feed(_authz_denied_logon_response(with_sys_id=False))
    assert ei.value.key == "RFC_NO_AUTHORITY"
    assert sess.state is not SessionState.READY


def test_allow_restricted_logon_without_sys_id_opens() -> None:
    """allow_restricted_logon salvages the 7.52 shape too (no 0x0450).

    The salvage decision keys on 0x0420 (logon completed), so a 7.52 reply that omits
    0x0450 but authenticated and was S_RFC-denied still reaches READY.
    """
    sess = Session(allow_restricted_logon=True)
    _drive_to_logon(sess)
    sess.feed(_authz_denied_logon_response(with_sys_id=False))
    assert sess.state is SessionState.READY
    assert sess.attributes is not None


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
