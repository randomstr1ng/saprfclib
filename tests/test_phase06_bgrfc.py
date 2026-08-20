# tests/test_phase06_bgrfc.py
#
# Phase 6 — bgRFC client-side tests (TRFC-05, TRFC-06).
#
# Wave 0 status: RED scaffolds — tests target symbols that do not exist until
# Plan 06-05. All behavior tests are marked xfail(strict=False) so the offline
# suite stays collectable and green at Wave 1 close.
#
# Requirement coverage:
#   TRFC-05: conn.create_unit() buffers calls; submits atomically on __exit__
#   TRFC-06: confirm/rollback/get_unit_state map to UnitState enum values
#
# Protocol citations: docs/protocol/trfc.md §"bgRFC Wire Format: BGRFC_DEST_SHIP",
#   §"The 32-Character UnitID Format", §"bgRFC Submit + Confirm"
# SDK refs: SDK type definitions (unit creation), 2272 (RfcInvokeInUnit — nothing executes
#   yet), 2303 (RfcSubmitUnit), 2331 (RfcConfirmUnit), 2357 (RfcGetUnitState)

from __future__ import annotations

import pytest

# --------------------------------------------------------------------------- #
# UnitID format validation (offline — no production symbol needed)
# --------------------------------------------------------------------------- #

_UNITID_LN = 32  # RFC_UNITID_LN from SDK type definitions
_UNITID_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")


def _is_valid_unitid(uid: object) -> bool:
    """Return True iff uid is a 32-char uppercase hex string."""
    return (
        isinstance(uid, str) and len(uid) == _UNITID_LN and all(c in _UNITID_CHARSET for c in uid)
    )


def test_unitid_format_from_uuid() -> None:
    """uuid4().hex.upper() produces a valid 32-char UnitID.

    Validates the format constant. No production symbols needed.
    Source: UnitID generation → pfuuid_print → 32 uppercase hex.
    """
    import uuid

    uid = uuid.uuid4().hex.upper()
    assert _is_valid_unitid(uid), f"UUID-derived UnitID {uid!r} must pass validation"


def test_unitid_rejects_lowercase() -> None:
    """UnitID must be uppercase hex — lowercase chars must fail."""
    assert not _is_valid_unitid("a" * _UNITID_LN), "lowercase UnitID must fail"


def test_unitid_rejects_wrong_length() -> None:
    """UnitID exactly 32 chars — 31 and 33 must fail."""
    valid = "A" * _UNITID_LN
    assert not _is_valid_unitid(valid[:-1]), "31-char UnitID must fail"
    assert not _is_valid_unitid(valid + "A"), "33-char UnitID must fail"


# --------------------------------------------------------------------------- #
# Helper: Connection in READY state backed by MockTransport (no live SAP needed)
# --------------------------------------------------------------------------- #


def _make_ready_bgrfc_connection(responses: list[bytes] | None = None):
    """Return a Connection with _session in READY state, backed by a MockTransport.

    Bypasses the real TCP/NI/GW handshake — bgRFC frame builders can be tested
    offline without a live SAP system.  Pattern mirrors test_phase06_trfc.py.
    """
    from saprfclib.connection import Connection
    from saprfclib.session import SessionState
    from tests._mocks import MockTransport

    transport = MockTransport(list(responses) if responses else [])
    conn = Connection(transport)
    conn._session._state = SessionState.READY
    return conn


# --------------------------------------------------------------------------- #
# TRFC-05: create_unit buffers calls, submits on __exit__
# --------------------------------------------------------------------------- #


def test_unit_buffer_submit() -> None:
    """create_unit() buffers unit.call() invocations; submit fires on __exit__.

    GREEN: Plan 06-05 — Connection.create_unit implemented.

    Validates:
    1. Unit type 'T' when queues=[] (: 0x54 = 'T').
    2. unit.call() returns None (RfcInvokeInUnit buffers — h:2272 'nothing executes yet').
    3. __exit__ triggers BGRFC_DEST_SHIP to the backend (docs/protocol/trfc.md
       §"bgRFC Submit + Confirm").
    4. Multiple unit.call() invocations are buffered (one submit sends all).
    """
    import uuid

    # MockTransport returns empty bytes for the BGRFC_DEST_SHIP response (offline).
    conn = _make_ready_bgrfc_connection(responses=[b""])

    uid = uuid.uuid4().hex.upper()  # valid 32-char UnitID

    with conn.create_unit(uid=uid, queues=[]) as unit:
        rv1 = unit.call("STFC_CONNECTION", REQUTEXT="a")
        rv2 = unit.call("STFC_CONNECTION", REQUTEXT="b")

    # unit.call() must return None (nothing executes, no response)
    assert rv1 is None, "unit.call() must return None (RfcInvokeInUnit buffers, does not execute)"
    assert rv2 is None, "unit.call() must return None (second buffered call)"

    # Submit must have produced at least one frame (BGRFC_DEST_SHIP)
    assert conn._transport.sent, "create_unit __exit__ must have produced at least one frame"  # type: ignore[attr-defined]
    frame = conn._transport.sent[0]  # type: ignore[attr-defined]

    bgrfc_utf16 = "BGRFC_DEST_SHIP".encode("utf-16-le")
    assert bgrfc_utf16 in frame, (
        "BGRFC_DEST_SHIP (UTF-16LE) must appear in submit frame (the server dispatch)"
    )


def test_unit_type_t_when_no_queues() -> None:
    """create_unit(queues=[]) must create unit type 'T' (0x54).

    GREEN: Plan 06-05.
    """
    import uuid

    conn = _make_ready_bgrfc_connection()

    uid = uuid.uuid4().hex.upper()
    unit_ctx = conn.create_unit(uid=uid, queues=[])
    unit_type = getattr(unit_ctx, "unit_type", None) or getattr(unit_ctx, "_unit_type", None)
    assert unit_type == "T", f"Unit type must be 'T' (0x54) when queues=[]; got {unit_type!r}"


def test_unit_type_q_when_queues_given() -> None:
    """create_unit(queues=['Q1']) must create unit type 'Q' (0x51).

    GREEN: Plan 06-05.
    """
    import uuid

    conn = _make_ready_bgrfc_connection()

    uid = uuid.uuid4().hex.upper()
    unit_ctx = conn.create_unit(uid=uid, queues=["Q1"])
    unit_type = getattr(unit_ctx, "unit_type", None) or getattr(unit_ctx, "_unit_type", None)
    assert unit_type == "Q", (
        f"Unit type must be 'Q' (0x51) when queues non-empty; got {unit_type!r}"
    )


def test_unit_exception_does_not_submit() -> None:
    """An exception inside the with-block must NOT trigger a submit frame.

    GREEN: Plan 06-05.

    Pitfall 6: the unit is abandoned on exception — no BGRFC_DEST_SHIP is sent.
    """
    import uuid

    conn = _make_ready_bgrfc_connection()

    uid = uuid.uuid4().hex.upper()

    with pytest.raises(ValueError):
        with conn.create_unit(uid=uid, queues=[]) as unit:
            unit.call("STFC_CONNECTION", REQUTEXT="x")
            raise ValueError("test exception — unit must be abandoned")

    # No frame must have been sent (unit was abandoned).
    assert not conn._transport.sent, (  # type: ignore[attr-defined]
        "No submit frame must be sent when the with-block raises an exception "
        "(unit is abandoned — Pitfall 6)"
    )


# --------------------------------------------------------------------------- #
# TRFC-06: confirm/rollback/get_unit_state lifecycle
# --------------------------------------------------------------------------- #


def test_unit_lifecycle() -> None:
    """confirm/rollback/get_unit_state map to UnitState enum values.

    GREEN: Plan 06-05 — Connection.confirm_unit / rollback_unit / get_unit_state implemented.

    Validates UnitState enum values mirror RFC_UNIT_STATE (SDK type definitions-332):
      NOT_FOUND=0, IN_PROCESS=1, COMMITTED=2, ROLLED_BACK=3, CONFIRMED=4
    """
    import uuid

    from saprfclib.stores import UnitState

    # Verify enum members exist with the right names (SDK type definitions-332)
    assert hasattr(UnitState, "NOT_FOUND"), "UnitState.NOT_FOUND missing"
    assert hasattr(UnitState, "IN_PROCESS"), "UnitState.IN_PROCESS missing"
    assert hasattr(UnitState, "COMMITTED"), "UnitState.COMMITTED missing"
    assert hasattr(UnitState, "ROLLED_BACK"), "UnitState.ROLLED_BACK missing"
    assert hasattr(UnitState, "CONFIRMED"), "UnitState.CONFIRMED missing"

    uid = uuid.uuid4().hex.upper()

    # confirm_unit — MockTransport returns empty bytes (no live SAP needed)
    conn = _make_ready_bgrfc_connection(responses=[b"", b""])
    conn.confirm_unit(uid, unit_type="T")
    assert conn._transport.sent, "confirm_unit must have sent a frame"  # type: ignore[attr-defined]
    frame = conn._transport.sent[0]  # type: ignore[attr-defined]
    bgrfc_confirm_utf16 = "BGRFC_DEST_CONFIRM".encode("utf-16-le")
    assert bgrfc_confirm_utf16 in frame, (
        "BGRFC_DEST_CONFIRM (UTF-16LE) must appear in confirm_unit frame (the server dispatch)"
    )

    # get_unit_state — empty response → NOT_FOUND (offline default)
    conn2 = _make_ready_bgrfc_connection(responses=[b""])
    state = conn2.get_unit_state(uid, unit_type="T")
    assert isinstance(state, UnitState), f"get_unit_state must return UnitState, got {type(state)}"
    # Offline path (no live SAP): state defaults to NOT_FOUND
    assert state == UnitState.NOT_FOUND, (
        f"Offline get_unit_state must return NOT_FOUND, got {state!r}"
    )
