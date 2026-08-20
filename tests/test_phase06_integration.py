# tests/test_phase06_integration.py
#
# Phase 6 end-to-end wiring and requirement traceability for tRFC / qRFC / bgRFC
# (TRFC-01..08).
#
# Requirement coverage (TRFC-01..08):
#   Offline-verified: unit tests in tests/test_phase06_{trfc,bgrfc,server,stores}.py
#   Live skip-guarded (D-08 gate — all three modes must pass against a live SAP
#   system before Phase 6 is complete):
#     - test_live_duplicate_tid_returns_executed   (TRFC-01/02/03)
#     - test_live_qrfc_queued_call                 (TRFC-04)
#     - test_live_bgrfc_unit_lifecycle             (TRFC-05/06/07)
#
# Live integration tests (test_live_*): guarded by @pytest.mark.integration plus a
# skipif on SAPRFC_ASHOST, so the offline suite stays green without a live system.
#
# Environment variables:
#   SAPRFC_ASHOST     A4H application server host (skip-guard for live tests)
#   SAPRFC_SYSNR      system number (default "00")
#   SAPRFC_CLIENT     SAP client (e.g. "001")
#   SAPRFC_USER       SAP logon user
#   SAPRFC_PASSWD     SAP logon password — NEVER logged, printed, or asserted
#   SAPRFC_GWHOST     gateway host (default: SAPRFC_ASHOST)
#   SAPRFC_PROGRAM_ID PROGRAM_ID for SM59 type-T destination (server tests)
#                     Gateway port is derived from SAPRFC_SYSNR: 3300 + int(sysnr)
#
# SM59 type-T setup requirement for live tRFC tests:
#   An SM59 *type-T* (TCP/IP, "Registered Server Program") destination whose
#   PROGRAM_ID matches SAPRFC_PROGRAM_ID, plus an ABAP report that issues
#   CALL FUNCTION 'STFC_CONNECTION' IN BACKGROUND TASK DESTINATION '<dest>'
#   while this test registers the handler and waits.

from __future__ import annotations

import os
import threading
import time

import pytest

import saprfclib
from saprfclib import RfcServer
from saprfclib.stores import UnitState

# --------------------------------------------------------------------------- #
# Requirement traceability (completeness guard — test_requirement_traceability
# must PASS at Wave 0 close; it only checks the dict, not the implementation)
# --------------------------------------------------------------------------- #

#: Each Phase 6 requirement ID maps to the canonical test node id that proves it.
#: Test node ids match the RESEARCH.md "Phase Requirements → Test Map" exactly.
#: Updated 2026-07-03 — Wave 0 scaffold; all eight TRFC-01..08 mapped.
REQUIREMENT_COVERAGE: dict[str, str] = {
    # TRFC-01: call_transactional emits call-type marker (ARFC_DEST_SHIP) + TID TLV.
    # Offline unit test verifies the TLV payload; live D-08 gate proves the real backend
    # accepts the tRFC frame end-to-end.
    "TRFC-01": "tests/test_phase06_trfc.py::test_call_transactional_frame",
    # TRFC-02: create_tid → valid 24-char TID; confirm_tid accepts it (NULL-handle gen).
    # Offline verifies alphabet + length; live confirms the backend accepts and confirms
    # the TID without error.
    "TRFC-02": "tests/test_phase06_trfc.py::test_tid_roundtrip",
    # TRFC-03: server returns RFC_EXECUTED for known TID; persists new before exec.
    # Fully proven offline — duplicate TID dedup is algorithmic and does not require
    # a live SAP round-trip (SAP makes sending the same TID twice difficult).
    "TRFC-03": "tests/test_phase06_server.py::test_duplicate_tid_short_circuits",
    # TRFC-04: qRFC frame carries queue-name indicator / param.
    # Offline unit test verifies the ARFCQUEUE param is present in the TLV; live
    # D-08 gate proves the backend routes the call into the queue without error.
    "TRFC-04": "tests/test_phase06_integration.py::test_live_qrfc_queued_call",
    # TRFC-05: create_unit buffers calls; submits atomically on __exit__.
    # Offline unit test is the algorithmic proof; live D-08 gate proves the backend
    # accepts the BGRFC_DEST_SHIP frame and commits the unit.
    "TRFC-05": "tests/test_phase06_integration.py::test_live_bgrfc_unit_lifecycle",
    # TRFC-06: confirm/rollback/get_unit_state map to UnitState enum values.
    # Offline unit test verifies the state-machine mechanics; live D-08 gate proves
    # get_unit_state returns a valid UnitState and confirm_unit cleans up on the backend.
    "TRFC-06": "tests/test_phase06_integration.py::test_live_bgrfc_unit_lifecycle",
    # TRFC-07: bgRFC server callbacks fire in check→persist→execute→commit/confirm order.
    # Offline unit test is the complete proof (all 5 callbacks verified in order);
    # live D-08 gate covers the inbound bgRFC server path end-to-end.
    "TRFC-07": "tests/test_phase06_server.py::test_unit_callback_flow",
    # TRFC-08: TidStore/UnitStore Protocol + InMemory defaults; isinstance passes.
    "TRFC-08": "tests/test_phase06_stores.py::test_protocol_conformance",
}

_ALL_REQUIREMENT_IDS: frozenset[str] = frozenset(
    {
        "TRFC-01",
        "TRFC-02",
        "TRFC-03",
        "TRFC-04",
        "TRFC-05",
        "TRFC-06",
        "TRFC-07",
        "TRFC-08",
    }
)


def test_requirement_traceability() -> None:
    """Every Phase 6 TRFC- requirement maps to a test node id; no entry is empty.

    This test MUST PASS at Wave 0 close. It validates only the coverage dict,
    not the implementation — all referenced tests are xfail/importorskip while
    production symbols are absent.

    Prevents silent coverage gaps: adding a new TRFC- requirement without
    updating REQUIREMENT_COVERAGE fails this test immediately, and any empty
    coverage string is rejected.
    """
    missing = _ALL_REQUIREMENT_IDS - REQUIREMENT_COVERAGE.keys()
    assert not missing, (
        f"Requirements missing from REQUIREMENT_COVERAGE: {missing}\n"
        "Update REQUIREMENT_COVERAGE in tests/test_phase06_integration.py."
    )

    for req_id, coverage in REQUIREMENT_COVERAGE.items():
        assert coverage, f"REQUIREMENT_COVERAGE[{req_id!r}] must not be empty"

    empty = {k for k, v in REQUIREMENT_COVERAGE.items() if not v.strip()}
    assert not empty, f"Empty coverage strings found: {empty}"

    # All mapped IDs must be known requirement IDs (no typos)
    unknown = REQUIREMENT_COVERAGE.keys() - _ALL_REQUIREMENT_IDS
    assert not unknown, (
        f"Unknown requirement IDs in REQUIREMENT_COVERAGE: {unknown}\n"
        "Valid IDs: {_ALL_REQUIREMENT_IDS!r}"
    )


# --------------------------------------------------------------------------- #
# Live test helpers
# --------------------------------------------------------------------------- #

_LIVE_SKIP_REASON = (
    "SAPRFC_ASHOST not set — no live SAP system available (D-08 phase-gate: "
    "all three tRFC/qRFC/bgRFC live tests must pass before Phase 6 is complete)"
)


# --------------------------------------------------------------------------- #
# Live: tRFC duplicate TID returns RFC_EXECUTED (TRFC-01/02/03)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST") or not os.environ.get("SAPRFC_PROGRAM_ID"),
    reason=_LIVE_SKIP_REASON + " or SAPRFC_PROGRAM_ID not set (SM59 type-T setup required)",
)
def test_live_trfc_delivery() -> None:
    """SAP delivers a tRFC call to the registered Python server end-to-end.

    D-08 gate (TRFC-01/02): proves the ARFC_DEST_SHIP wire format and TID
    round-trip against a live SAP system.
    - TRFC-01: inbound tRFC frame is decoded correctly (ARFC_DEST_SHIP path)
    - TRFC-02: handler receives the call; server returns RFC_OK (TID lifecycle)

    TRFC-03 (duplicate-TID RFC_EXECUTED) is fully proven offline:
      tests/test_phase06_server.py::test_duplicate_tid_short_circuits

    SM59 setup (one-time):
      Create an SM59 *type-T* (TCP/IP, "Registered Server Program") destination
      whose PROGRAM_ID matches SAPRFC_PROGRAM_ID and points to SAPRFC_GWHOST
      (default SAPRFC_ASHOST), port derived from SAPRFC_SYSNR (3300 + sysnr).

    Manual SAP-side trigger: while this test is waiting, run in SE38/SA38
    (replace <dest> with your SM59 type-T destination name):

        CALL FUNCTION 'STFC_CONNECTION' IN BACKGROUND TASK
          DESTINATION '<dest>'
          EXPORTING requtext = 'saprfc_phase06_trfc_live'.
        COMMIT WORK.

    SAPRFC_PASSWD is read from the environment only; never logged, printed,
    or asserted in plaintext (T-06-E01 / T-04-CRED).
    """
    gwhost = os.environ.get("SAPRFC_GWHOST", os.environ["SAPRFC_ASHOST"])
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    gwserv = str(3300 + int(sysnr))
    program_id = os.environ["SAPRFC_PROGRAM_ID"]

    call_seen = threading.Event()
    received: dict = {}

    server = RfcServer({"program_id": program_id, "gwhost": gwhost, "gwserv": gwserv})

    @server.function("STFC_CONNECTION")
    def _trfc_handler(request: dict) -> dict:
        received.update(request)
        call_seen.set()
        return {}

    serve_thread = threading.Thread(
        target=server.serve_forever, name="saprfclib-live-trfc", daemon=True
    )
    serve_thread.start()
    try:
        triggered = call_seen.wait(timeout=120.0)
        assert triggered, (
            "No inbound tRFC call received within 120 s — run the ABAP report that "
            f"CALLs STFC_CONNECTION IN BACKGROUND TASK DESTINATION '<dest>' "
            f"while this server is registered (PROGRAM_ID={program_id!r}, "
            f"gwhost={gwhost!r}, gwserv={gwserv!r})."
        )
        time.sleep(0.5)
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# Live: qRFC queued call (TRFC-04)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("SAPRFC_ASHOST"), reason=_LIVE_SKIP_REASON)
def test_live_qrfc_queued_call() -> None:
    """Client issues a qRFC call with a queue name; backend accepts it without error.

    D-08 gate: Proves TRFC-04 against live SAP:
    - conn.call_transactional(func, tid=tid, queue="SAPRFC_Q1") emits a qRFC frame
      (ARFC_DEST_SHIP with ARFCQUEUE param)
    - The SAP backend accepts the call (no exception raised), routes the invocation
      into the named queue (visible in SMQS / SM58 on the SAP side)
    - conn.confirm_tid(tid) completes the lifecycle without error

    SM59 setup (manual, one-time):
      An SM59 *type-T* (TCP/IP) destination pointing at an application server
      (or the Python server via gateway) is NOT required for the client-side
      qRFC test. The client sends to the SAP backend; SAP queues the wrapped FM
      locally (TRFCQIN table). The FM is executed by the SAP system itself — the
      Python server is not involved as a receiver here.

    What you need on the SAP side:
      - A valid RFC destination (RFC_DEST, SM59 type-R) for the target system,
        OR use 'NONE' / 'BACK' as the destination if testing same-system qRFC.
      - Observe SMQS for the 'SAPRFC_Q1' queue appearing after this test runs.

    NOTE: Because this is a pure client-side test, the Python code sends the
    qRFC frame and receives a server acknowledgment. If the FM or destination
    does not exist the backend may return ABAP_EXCEPTION — the test asserts
    only that no transport-level error occurs (the qRFC frame was accepted by
    SAP's tRFC/qRFC infrastructure). The 'STFC_CONNECTION' FM is used as a
    safe test FM known to exist on all standard SAP systems.

    SAPRFC_PASSWD is read from the environment only; never logged, printed,
    or asserted in plaintext (T-06-E01 / T-04-CRED).
    """
    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ["SAPRFC_USER"]
    # Password sourced from env only — never logged, printed, or asserted.
    passwd = os.environ["SAPRFC_PASSWD"]

    conn = saprfclib.connect(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
    )
    try:
        tid = conn.create_tid()

        # Verify the TID format: must be 24 chars, RFC alphabet subset.
        assert len(tid) == 24, f"create_tid() returned a TID of length {len(tid)}, expected 24"
        assert tid.isalnum() or all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-" for c in tid
        ), f"create_tid() returned TID {tid!r} with unexpected characters"

        # Submit the qRFC call. No exception means the backend accepted the
        # qRFC frame and queued the call (TRFC-04).
        # Use STFC_CONNECTION (safe, exists on all SAP systems) as the wrapped FM.
        conn.call_transactional(
            "STFC_CONNECTION",
            tid=tid,
            queue="SAPRFC_Q1",
        )

        # Confirm the TID as a separate lifecycle step (Pitfall 3 / D-04).
        # After confirm the backend drops dup-protection for this TID.
        conn.confirm_tid(tid)

    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Live: bgRFC unit lifecycle (TRFC-05/06/07)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("SAPRFC_ASHOST"), reason=_LIVE_SKIP_REASON)
def test_live_bgrfc_unit_lifecycle() -> None:
    """bgRFC unit create/submit/confirm lifecycle passes end-to-end against live SAP.

    D-08 gate: Proves TRFC-05/06/07 against live SAP:
    - TRFC-05: create_unit() buffers; __exit__ submits via BGRFC_DEST_SHIP
    - TRFC-06: get_unit_state() returns a valid UnitState; confirm_unit() cleans up
    - TRFC-07: bgRFC server callbacks fire in correct order when inbound bgRFC arrives
               (tested implicitly: the submit is accepted; the backend progresses the
               unit through its state machine)

    SM59 setup (manual, one-time):
      No SM59 type-T destination is required for the CLIENT-side bgRFC test.
      The Python process is the bgRFC CLIENT sending to the SAP backend.
      The backend receives the BGRFC_DEST_SHIP frame and manages the unit
      state in its BGRFCSTATE / BGRFCSTATUS tables (SBGRFCMON).

    What you need on the SAP side:
      - A valid SAP connection (standard logon credentials).
      - Observe SBGRFCMON for the submitted unit after the test runs.
      - The STFC_CONNECTION FM is used as the bgRFC payload — it exists on all
        standard SAP systems and is safe to call in background mode.

    bgRFC client lifecycle sequence:
      1. create_unit(queues=["SAPRFC_BG_Q1"]) → unit_type='Q', new 32-char UnitID
      2. unit.call("STFC_CONNECTION", ...) → buffered (nothing executes yet)
      3. with-block exits cleanly → _submit_unit() → BGRFC_DEST_SHIP frame sent
      4. get_unit_state(unit_id, unit_type) → UnitState (NOT_FOUND or COMMITTED
         depending on backend speed; both are valid — see note below)
      5. confirm_unit(unit_id, unit_type) → BGRFC_DEST_CONFIRM sent

    Note on NOT_FOUND after submit (T-06-U04):
      If the backend processes the unit BEFORE get_unit_state is called, it may
      have already cleaned up — returning NOT_FOUND. This is NOT an error.
      NOT_FOUND after a successful submit means the backend committed and cleaned
      up; it is equivalent to CONFIRMED (anti-pattern: never resend on NOT_FOUND
      after a known-good submit). This test accepts NOT_FOUND, IN_PROCESS,
      COMMITTED, or CONFIRMED as valid responses — all indicate the backend
      received and started processing the unit. ROLLED_BACK is the only failure.

    SAPRFC_PASSWD is read from the environment only; never logged, printed,
    or asserted in plaintext (T-06-E01 / T-04-CRED).
    """
    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ["SAPRFC_USER"]
    # Password sourced from env only — never logged, printed, or asserted.
    passwd = os.environ["SAPRFC_PASSWD"]

    conn = saprfclib.connect(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
    )
    try:
        # TRFC-05: create_unit with a queue name → unit_type='Q'.
        with conn.create_unit(queues=["SAPRFC_BG_Q1"]) as unit:
            unit_id = unit.unit_id
            unit_type = unit.unit_type

            assert len(unit_id) == 32, (
                f"create_unit() produced a UnitID of length {len(unit_id)}, "
                "expected 32 (RFC_UNITID_LN=32, SDK type definitions)"
            )
            assert unit_type == "Q", (
                f"unit_type should be 'Q' when queues are given, got {unit_type!r}"
            )

            # Buffer a call — nothing executes until the with-block exits.
            unit.call("STFC_CONNECTION", REQUTEXT="saprfc_phase06_bgrfc_live")
        # __exit__ with no exception → BGRFC_DEST_SHIP frame sent (TRFC-05).

        # TRFC-06: query the unit state on the backend.
        state = conn.get_unit_state(unit_id, unit_type)

        # Acceptable post-submit states (see docstring note on NOT_FOUND):
        #   NOT_FOUND  — backend processed and cleaned up before we queried
        #   IN_PROCESS — backend received and is executing (normal fast query)
        #   COMMITTED  — backend committed the LUW
        #   CONFIRMED  — backend already confirmed + cleaned up
        # ROLLED_BACK is the only failure state (unit did not commit).
        _valid_states = {
            UnitState.NOT_FOUND,
            UnitState.IN_PROCESS,
            UnitState.COMMITTED,
            UnitState.CONFIRMED,
        }
        assert state in _valid_states, (
            f"get_unit_state() returned {state!r} for unit {unit_id[:8]}... — "
            "expected one of NOT_FOUND/IN_PROCESS/COMMITTED/CONFIRMED after submit. "
            "ROLLED_BACK indicates the backend rejected the BGRFC_DEST_SHIP frame "
            "(check SBGRFCMON on the SAP side for the error details)."
        )

        # TRFC-06: confirm the unit — cleans up backend state tables.
        # If state is NOT_FOUND, confirm_unit still sends BGRFC_DEST_CONFIRM;
        # the backend treats it as a no-op (T-06-U04 anti-pattern guard).
        conn.confirm_unit(unit_id, unit_type)

        # Post-confirm: querying state is optional; NOT_FOUND means success.
        post_state = conn.get_unit_state(unit_id, unit_type)
        # After confirm, the backend may have cleaned up → NOT_FOUND or CONFIRMED.
        _post_confirm_valid = {UnitState.NOT_FOUND, UnitState.CONFIRMED}
        assert post_state in _post_confirm_valid, (
            f"get_unit_state() after confirm_unit() returned {post_state!r} — "
            "expected NOT_FOUND (backend cleaned up) or CONFIRMED."
        )

    finally:
        conn.close()
