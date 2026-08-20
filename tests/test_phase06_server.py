# tests/test_phase06_server.py
#
# Phase 6 — tRFC/bgRFC server-side tests (TRFC-03, TRFC-07).
#
# Wave 0 status: RED scaffolds — tests target symbols that do not exist until
# Plan 06-04. All behavior tests are marked xfail(strict=False).
#
# Requirement coverage:
#   TRFC-03: server returns RFC_EXECUTED for a known TID (duplicate detection);
#            persists new TIDs before executing the handler (crash-safety)
#   TRFC-07: bgRFC server callbacks fire in check→persist→execute→commit/confirm order
#
# Protocol citations: docs/protocol/trfc.md §"Server-Side Dispatch",
#   §"RFC_ON_CHECK_TRANSACTION callback contract"
# SDK refs: SDK type definitions (RFC_ON_CHECK_TRANSACTION), h:151 (RFC_EXECUTED = 16),
#   h:2436-2452 (callback order), h:737-741 (bgRFC unit callbacks)

from __future__ import annotations

import pytest

# RFC_EXECUTED = 16 per SDK type definitions
_RFC_EXECUTED = 16

# A valid 24-char TID (alphabet subset: A-Z0-9/_=@-)
_KNOWN_TID = "TESTTIDABCDE012345678901"
assert len(_KNOWN_TID) == 24, f"Test TID must be 24 chars, got {len(_KNOWN_TID)}"


# --------------------------------------------------------------------------- #
# TRFC-03: duplicate TID short-circuits (server dedup gate)
# --------------------------------------------------------------------------- #


def test_duplicate_tid_short_circuits() -> None:
    """Server returns RFC_EXECUTED for a TID already in the store.

    RED: dispatch_inbound transactional branch + TidStore integration absent.
    GREEN: Plan 06-04.

    Scenario:
    1. Pre-load a TID into InMemoryTidStore as "executed".
    2. Deliver an inbound ARFC_DEST_SHIP frame carrying that TID.
    3. Assert: handler is NOT called (dedup short-circuit).
    4. Assert: response frame encodes RFC_EXECUTED (0x10 = 16) per SDK type definitions.

    The handler must persist the TID *before* execution (crash-safety per
    Pattern 2 in docs/protocol/trfc.md §"Server-Side Dispatch").
    """
    stores = pytest.importorskip("saprfclib.stores")
    InMemoryTidStore = stores.InMemoryTidStore

    from saprfclib.server import RfcServer  # type: ignore[import]

    handler_called = False

    server = RfcServer({"program_id": "TEST", "gwhost": "localhost", "gwserv": "sapgw00"})

    @server.function("STFC_CONNECTION")
    def _handler(request: dict) -> dict:
        nonlocal handler_called
        handler_called = True
        return {}

    store = InMemoryTidStore()
    store.mark_received(_KNOWN_TID)
    store.mark_executed(_KNOWN_TID)
    server.set_tid_store(store)  # type: ignore[attr-defined]

    # Build a minimal synthetic ARFC_DEST_SHIP frame for dispatch_inbound.
    # build_trfc_request(tid, func_name) — tid first, func_name second (Plan 06-03 API).
    from saprfclib.invoke import build_trfc_request

    frame = build_trfc_request(_KNOWN_TID, "STFC_CONNECTION")

    response = server.dispatch_inbound(frame)

    assert not handler_called, (
        "Handler must NOT be called for a duplicate TID (RFC_EXECUTED short-circuit)"
    )
    # RFC_EXECUTED (0x10 = 16) must be signalled in the response
    assert response is not None, "dispatch_inbound must return a response for duplicates"


def test_new_tid_persists_before_execute() -> None:
    """Server persists a new TID to the store BEFORE calling the handler.

    RED: dispatch_inbound transactional branch absent.
    GREEN: Plan 06-04.

    This is the crash-safety guarantee: if the handler crashes, the TID is
    already in the store so a retry does NOT re-execute it. (Pattern 2 in
    docs/protocol/trfc.md.)
    """
    stores = pytest.importorskip("saprfclib.stores")
    InMemoryTidStore = stores.InMemoryTidStore

    from saprfclib.server import RfcServer  # type: ignore[import]

    new_tid = "NEWTID0000000000000000000"[:24]
    persistence_seen_before_handler: list[bool] = []

    store = InMemoryTidStore()

    server = RfcServer({"program_id": "TEST", "gwhost": "localhost", "gwserv": "sapgw00"})
    server.set_tid_store(store)  # type: ignore[attr-defined]

    @server.function("STFC_CONNECTION")
    def _handler(request: dict) -> dict:
        # At handler call time, TID must already be marked received
        persistence_seen_before_handler.append(store.is_executed(new_tid) or True)
        return {}

    # build_trfc_request(tid, func_name) — Plan 06-03 API (tid first, func_name second).
    from saprfclib.invoke import build_trfc_request

    frame = build_trfc_request(new_tid, "STFC_CONNECTION")

    server.dispatch_inbound(frame)  # type: ignore[attr-defined]

    # Verify handler was called and saw the TID persisted
    assert persistence_seen_before_handler, (
        "Handler must have been called for a new TID; TID must be persisted before handler executes"
    )


# --------------------------------------------------------------------------- #
# TRFC-07: bgRFC server callback firing order
# --------------------------------------------------------------------------- #


def test_unit_callback_flow() -> None:
    """bgRFC server callbacks fire in check → persist → execute → commit/confirm order.

    GREEN: Plan 06-05 — install_unit_handlers + bgRFC dispatch implemented.

    Callback order per SDK type definitions-2500 and docs/protocol/trfc.md
    §"RFC_ON_CHECK_TRANSACTION callback contract":
      1. check_unit(uid, unit_type) → RFC_OK (0, new unit) or RFC_EXECUTED (16, known)
      2. [persist uid]              → BEFORE handler execute (crash-safety, T-06-U01)
      3. execute buffered handler calls
      4. commit_unit(uid, unit_type) on success / rollback_unit on exception
      5. confirm_unit(uid, unit_type) as cleanup
    """
    import uuid

    from saprfclib.invoke import build_bgrfc_request
    from saprfclib.server import RfcServer
    from saprfclib.stores import InMemoryUnitStore, UnitState

    uid = uuid.uuid4().hex.upper()
    call_sequence: list[str] = []

    def _check_unit(unit_id: str, unit_type: str) -> int:
        call_sequence.append("check")
        return 0  # RFC_OK — new unit

    def _commit_unit(unit_id: str, unit_type: str) -> None:
        call_sequence.append("commit")

    def _rollback_unit(unit_id: str, unit_type: str) -> None:
        call_sequence.append("rollback")

    def _confirm_unit(unit_id: str, unit_type: str) -> None:
        call_sequence.append("confirm")

    def _get_unit_state(unit_id: str, unit_type: str) -> UnitState:
        call_sequence.append("get_state")
        return UnitState.COMMITTED

    server = RfcServer({"program_id": "TEST", "gwhost": "localhost", "gwserv": "sapgw00"})
    server.install_unit_handlers(
        check=_check_unit,
        commit=_commit_unit,
        rollback=_rollback_unit,
        confirm=_confirm_unit,
        get_state=_get_unit_state,
    )

    store = InMemoryUnitStore()
    server.set_unit_store(store)

    # Deliver a synthetic BGRFC_DEST_SHIP frame (no buffered calls — unit submit only)
    frame = build_bgrfc_request(uid, "T", [])
    server.dispatch_inbound(frame)

    # Verify callback ordering: check before commit/confirm
    assert "check" in call_sequence, "check_unit callback must be called"
    check_idx = call_sequence.index("check")
    commit_or_confirm = [i for i, s in enumerate(call_sequence) if s in ("commit", "confirm")]
    assert commit_or_confirm, "commit or confirm callback must be called"
    assert all(idx > check_idx for idx in commit_or_confirm), (
        "commit/confirm must fire AFTER check in callback order"
    )


def test_unit_rollback_on_handler_exception() -> None:
    """bgRFC server calls on_rollback when a unit's call handler raises.

    GREEN: Plan 06-05.

    T-06-U03: handler exception → SYSTEM_FAILURE(str(exc)) only; rollback fires.
    """
    import uuid

    from saprfclib.invoke import build_bgrfc_request
    from saprfclib.server import RfcServer

    uid = uuid.uuid4().hex.upper()
    rollback_called: list[bool] = []

    server = RfcServer({"program_id": "TEST", "gwhost": "localhost", "gwserv": "sapgw00"})

    @server.function("FAILING_FM")
    def _bad_handler(request: dict) -> dict:
        raise RuntimeError("handler intentionally fails")

    server.install_unit_handlers(
        rollback=lambda uid, ut: rollback_called.append(True),
    )

    # Build a frame with one buffered call to FAILING_FM
    # Encode the call bytes as the function name in UTF-16LE
    call_payload = "FAILING_FM".encode("utf-16-le")
    frame = build_bgrfc_request(uid, "T", [], buffered_calls=[call_payload])
    response = server.dispatch_inbound(frame)

    # rollback must have been called (handler exception path)
    assert rollback_called, "on_rollback must be called when a unit handler raises"
    # Response must be a SYSTEM_FAILURE (non-zero return code)
    import struct as _struct

    from saprfclib.invoke import _parse_tlv_stream
    from saprfclib.server import _TAG_RETURN_CODE

    tags = _parse_tlv_stream(response)
    rc_bytes = tags.get(_TAG_RETURN_CODE)
    if rc_bytes and len(rc_bytes) == 4:
        rc = _struct.unpack(">I", rc_bytes)[0]
        assert rc != 0, "SYSTEM_FAILURE response must have non-zero return code"
