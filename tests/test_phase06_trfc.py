# tests/test_phase06_trfc.py
#
# Phase 6 — tRFC / qRFC client-side tests (TRFC-01, TRFC-02, TRFC-04).
#
# Wave 0 status: RED scaffolds — tests target symbols that do not exist until
# Plan 06-02/06-03.  All behavior tests were marked xfail(strict=False) so the
# offline suite remained collectable and green at Wave 1 close while correctly
# failing when the xfail marker is removed in later waves.
#
# Plan 06-03 (this plan): xfail markers removed; tests now GREEN.
#
# Test approach: uses Connection + MockTransport directly (no real TCP
# connection), with _session._state forced to READY, to exercise the
# outbound frame builder without a live SAP system.
#
# Requirement coverage:
#   TRFC-01: call_transactional emits call-type marker (ARFC_DEST_SHIP) + TID TLV
#   TRFC-02: create_tid produces a valid 24-char TID; confirm_tid accepts it
#   TRFC-04: qRFC frame carries queue-name indicator in ARFCSSTATE table param
#
# Protocol citations: docs/protocol/trfc.md §"Call-Type Discriminator",
#   §"tRFC Wire Format: ARFC_DEST_SHIP", §"The 24-Character TID Format",
#   §"qRFC: Queue-Name Discrimination"

from __future__ import annotations

import string

# --------------------------------------------------------------------------- #
# TRFC-02: TID character-set validation (offline — no production symbol needed)
# --------------------------------------------------------------------------- #

#: Valid TID alphabet per BN 0x4b5a33 (ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-)
_TID_ALPHABET: frozenset[str] = frozenset(string.ascii_uppercase + string.digits + "/_=@-")
_TID_LN = 24  # RFC_TID_LN from sapnwrfc.h:79


def _is_valid_tid(tid: object) -> bool:
    """Return True iff tid is a 24-char string over the BN-confirmed TID alphabet."""
    return isinstance(tid, str) and len(tid) == _TID_LN and all(c in _TID_ALPHABET for c in tid)


# TRFC-02 offline property: uuid4()-derived TID (uppercase hex subset) is valid
def test_tid_alphabet_subset_accepts_uuid_hex() -> None:
    """UUID hex (A-Z0-9) is a subset of the TID alphabet — offline, always passes.

    Validates the alphabet constant itself. Does NOT require saprfclib symbols.
    BN source: RfcTransaction::createTid 0x4b5a33 (41-char alphabet).
    """
    import uuid

    candidate = uuid.uuid4().hex[:_TID_LN].upper()
    assert _is_valid_tid(candidate), (
        f"UUID hex TID {candidate!r} must satisfy the TID alphabet check"
    )


def test_tid_alphabet_rejects_lowercase() -> None:
    """TID alphabet is uppercase only — lowercase chars must fail validation."""
    assert not _is_valid_tid("abcdefghijklmnopqrstuvwx"), "lowercase TID must fail"


def test_tid_alphabet_rejects_wrong_length() -> None:
    """TID exactly 24 chars — 23 and 25 must fail."""
    valid_base = "A" * _TID_LN
    assert not _is_valid_tid(valid_base[:-1]), "23-char TID must fail"
    assert not _is_valid_tid(valid_base + "A"), "25-char TID must fail"


# --------------------------------------------------------------------------- #
# Helper: Connection in READY state backed by MockTransport
# --------------------------------------------------------------------------- #


def _make_ready_connection(extra_responses: list[bytes] | None = None):
    """Return a Connection with _session in READY state, backed by a MockTransport.

    This bypasses the real TCP/NI/GW handshake so the tRFC frame builders can
    be tested offline without a live SAP system.  The approach mirrors the
    Phase 4 integration tests that manually script MockTransport.

    The READY state is forced directly on the session (the same pattern used by
    other offline unit tests in this test suite).
    """
    from saprfclib.connection import Connection
    from saprfclib.session import SessionState
    from tests._mocks import MockTransport

    responses = list(extra_responses) if extra_responses else []
    transport = MockTransport(responses)
    conn = Connection(transport)
    # Force session to READY without the real handshake.
    conn._session._state = SessionState.READY
    return conn


# --------------------------------------------------------------------------- #
# TRFC-01: call_transactional emits ARFC_DEST_SHIP + TID in frame
# --------------------------------------------------------------------------- #


def test_call_transactional_frame() -> None:
    """call_transactional() emits an invoke frame for ARFC_DEST_SHIP with TID.

    GREEN: Plan 06-03 — call_transactional wraps build_trfc_request().
    Assertion: the outbound byte stream contains 'ARFC_DEST_SHIP' (UTF-16LE)
    in the function-name TLV 0x0102 and the 48-byte TID value in an ARFCSSTATE
    param (docs/protocol/trfc.md §"Call-Type Discriminator").
    """
    conn = _make_ready_connection()

    tid = "A" * _TID_LN  # valid TID — all-A is alphabet-conformant

    try:
        conn.call_transactional("STFC_CONNECTION", tid=tid)
    except Exception:
        pass  # Transport will raise EOFError; we only care the frame was built

    assert conn._transport.sent, "call_transactional must have produced at least one frame"  # type: ignore[attr-defined]
    frame = conn._transport.sent[0]  # type: ignore[attr-defined]

    # Function name 'ARFC_DEST_SHIP' in UTF-16LE must appear in the frame
    arfc_utf16 = "ARFC_DEST_SHIP".encode("utf-16-le")
    assert arfc_utf16 in frame, (
        "ARFC_DEST_SHIP (UTF-16LE) not found in outbound frame "
        "(BN RfcServer::dispatch 0x4bb5de — function name IS the discriminator)"
    )

    # TID must appear in the frame (24 chars → 48 bytes UTF-16LE, Pitfall 4)
    tid_utf16 = tid.encode("utf-16-le")
    assert tid_utf16 in frame, (
        "TID value (UTF-16LE) not found in outbound frame "
        "(docs/protocol/trfc.md §'The 24-Character TID Format')"
    )


# --------------------------------------------------------------------------- #
# TRFC-02: create_tid / confirm_tid round-trip
# --------------------------------------------------------------------------- #


def test_tid_roundtrip() -> None:
    """create_tid() returns a valid 24-char TID; confirm_tid() accepts it without error.

    GREEN: Plan 06-03.
    """
    conn = _make_ready_connection()

    tid = conn.create_tid()

    assert _is_valid_tid(tid), (
        f"create_tid() must return a 24-char TID over "
        f"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@- alphabet; got {tid!r}"
    )

    # confirm_tid: issues ARFC_DEST_CONFIRM to backend (connection not live — EOFError OK)
    try:
        conn.confirm_tid(tid)
    except Exception:
        # Transport exhausted (EOFError) — acceptable; API must exist and have sent a frame.
        pass

    # At least one frame was sent (the ARFC_DEST_CONFIRM call)
    assert conn._transport.sent, "confirm_tid must send at least one frame"  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# TRFC-04: qRFC frame carries queue-name indicator
# --------------------------------------------------------------------------- #


def test_qrfc_queue_name() -> None:
    """call_transactional(..., queue='TESTQUEUE') includes queue-name in frame.

    GREEN: Plan 06-03.
    Assertion: outbound frame contains 'TESTQUEUE' (UTF-16LE) in the ARFCSSTATE
    table param — BN 0x4bb632: r13_1[0xe58].b != 0 → qRFC branch.
    """
    conn = _make_ready_connection()

    tid = "A" * _TID_LN
    queue_name = "TESTQUEUE"

    try:
        conn.call_transactional("STFC_CONNECTION", tid=tid, queue=queue_name)
    except Exception:
        pass

    assert conn._transport.sent, "qRFC call must produce a frame"  # type: ignore[attr-defined]
    frame = conn._transport.sent[0]  # type: ignore[attr-defined]

    assert queue_name.encode("utf-16-le") in frame, (
        f"Queue name '{queue_name}' (UTF-16LE) must appear in qRFC frame "
        f"(BN RfcServer::dispatch 0x4bb632 — 0xe58 byte is qRFC indicator)"
    )


# --------------------------------------------------------------------------- #
# Regression guard: sync call() path unaffected (Pitfall 2)
# --------------------------------------------------------------------------- #


def test_sync_regression_not_arfc_dest_ship() -> None:
    """Synchronous call() does NOT emit ARFC_DEST_SHIP as function name.

    Ensures call_transactional additions do not bleed into the sync call() path.
    We check the sync path would use a different function name TLV.
    This is a build_invoke_request unit regression — no Connection needed.
    """
    from saprfclib.invoke import build_invoke_request
    from saprfclib.metadata import RFCTYPE_CHAR
    from saprfclib.types import RFC_EXPORT, FieldDesc, FunctionDesc

    # Minimal STFC_CONNECTION descriptor with REQUTEXT EXPORTING param.
    desc = FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            FieldDesc(
                name="REQUTEXT",
                rfctype=RFCTYPE_CHAR,
                nuc_length=255,
                nuc_offset=0,
                uc_length=510,
                uc_offset=0,
                decimals=0,
                unicode_mode=True,
                direction=RFC_EXPORT,
            ),
        ],
    )
    payload = build_invoke_request("STFC_CONNECTION", desc, {})

    # Sync payload must contain STFC_CONNECTION but NOT ARFC_DEST_SHIP
    assert "STFC_CONNECTION".encode("utf-16-le") in payload, (
        "sync call must embed func name as UTF-16LE in TLV 0x0102"
    )
    assert "ARFC_DEST_SHIP".encode("utf-16-le") not in payload, (
        "sync call must NOT embed ARFC_DEST_SHIP (regression from tRFC path)"
    )
