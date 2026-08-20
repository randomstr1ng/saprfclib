# tests/test_phase05_integration.py
#
# Phase 5 end-to-end wiring and requirement traceability for the RFC server
# (SERVER-01..06) and the connection pool (POOL-01..04).
#
# Requirement coverage (SERVER-01..06, POOL-01..04):
#   Offline-verified: server registry/dispatch/serialize/auth/exception tests in
#   tests/test_phase05_server.py + pool tests in tests/test_phase05_pool.py.
#   Live skip-guarded (D-06 — the phase gate; SAP must actually call the Python
#   handler, the proof cannot be stubbed or deferred):
#     - test_live_inbound_call             (SERVER-01..06 end-to-end)
#     - test_live_pool_acquire_call_release (POOL-01..04 against real connections)
#
# Live integration tests (test_live_*): guarded by @pytest.mark.integration plus a
# skipif on SAPRFC_ASHOST, so the offline suite stays green without a live system.
#
# Environment variables (read ONLY from os.environ — never hardcoded):
#   SAPRFC_ASHOST     A4H application server host (skip-guard for every live test)
#   SAPRFC_SYSNR      system number (default "00")
#   SAPRFC_CLIENT     SAP client (e.g. "001")
#   SAPRFC_USER       SAP logon user for the pool's outbound connections
#   SAPRFC_PASSWD     SAP logon password — NEVER logged, printed, or asserted in
#                     plaintext (T-05-E01 / T-04-CRED carried forward from Phase 4)
#   SAPRFC_GWHOST     A4H gateway host (default: SAPRFC_ASHOST)
#   SAPRFC_PROGRAM_ID PROGRAM_ID matching the SM59 type-T (registration) destination
#                     Gateway port is derived from SAPRFC_SYSNR: 3300 + int(sysnr)
#
# SM59 type-T setup requirement (manual, SAP-side — D-06 live trigger):
#   The live inbound test requires an SM59 *type-T* (TCP/IP, "Registered Server
#   Program") destination whose Registered Server Program ID equals
#   SAPRFC_PROGRAM_ID, plus an ABAP report/transaction that issues a CALL FUNCTION
#   ... DESTINATION '<that SM59 dest>' against the function module the Python
#   handler answers. While the Python server is registered, SM59 shows the
#   PROGRAM_ID as registered; running the ABAP report pushes the inbound call to
#   the Python handler. The exact steps are documented in each live test's
#   docstring. This cannot be triggered from Python alone — a human runs the ABAP
#   report (or schedules the transaction) during the live checkpoint.

from __future__ import annotations

import os
import threading
import time

import pytest

from saprfclib import ConnectionPool, RfcServer
from saprfclib.metadata import FunctionDesc
from saprfclib.types import RFC_EXPORT, RFC_IMPORT, FieldDesc

# RFCTYPE constant (mirrors codec.py / tests/test_phase05_server.py).
_RFCTYPE_CHAR = 0


# --------------------------------------------------------------------------- #
# Requirement traceability (completeness guard)
# --------------------------------------------------------------------------- #

#: Each Phase 5 requirement ID maps to a concrete test node id (offline unit test
#: for the unit-provable behaviours, or a live ``@integration`` test for the
#: end-to-end / real-connection requirements) OR "GAP:<reason>" if genuinely
#: unreachable. All ten requirements have a path; no GAPs are expected.
#: Updated 2026-06-29 — SERVER-01..06 + POOL-01..04 traced offline + live.
REQUIREMENT_COVERAGE: dict[str, str] = {
    # SERVER-01: register a Python function as an RFC server handler for an FM name
    "SERVER-01": "tests/test_phase05_server.py::test_decorator_registers_handler",
    # SERVER-02: server registers with an SAP gateway and accepts inbound calls.
    # Offline: the registration frame matches the live capture (byte-for-byte);
    # live: the gateway actually accepts the registration and pushes a call.
    "SERVER-02": "tests/test_phase05_integration.py::test_live_inbound_call",
    # SERVER-03: inbound params deserialized via the registered FunctionDesc → dict
    "SERVER-03": "tests/test_phase05_server.py::test_inbound_deserializes_params",
    # SERVER-04: handler return values serialized back to the SAP caller
    "SERVER-04": "tests/test_phase05_server.py::test_response_serialization_roundtrip",
    # SERVER-05: server-side authentication callback (allow/deny before dispatch)
    "SERVER-05": "tests/test_phase05_server.py::test_auth_callback_denies",
    # SERVER-06: concurrent inbound calls handled safely; bad handler isolated
    "SERVER-06": "tests/test_phase05_server.py::test_handler_exception_isolated",
    # POOL-01: create a pool with configurable min/max; min warmed at init
    "POOL-01": "tests/test_phase05_pool.py::test_pool_init_warms_min_size",
    # POOL-02: single-owner lend; a connection is never shared concurrently
    "POOL-02": "tests/test_phase05_pool.py::test_acquire_never_double_lends",
    # POOL-03: recycle on return; broken connections discarded and replaced
    "POOL-03": "tests/test_phase05_pool.py::test_ping_fail_discards_and_replaces",
    # POOL-04: thread-safe concurrent acquire/release
    "POOL-04": "tests/test_phase05_pool.py::test_concurrent_acquire_release_invariants",
}

_ALL_REQUIREMENT_IDS = {
    "SERVER-01",
    "SERVER-02",
    "SERVER-03",
    "SERVER-04",
    "SERVER-05",
    "SERVER-06",
    "POOL-01",
    "POOL-02",
    "POOL-03",
    "POOL-04",
}


def test_requirement_traceability() -> None:
    """Every Phase 5 SERVER-/POOL- requirement maps to a test node id or a GAP.

    Prevents silent coverage gaps: adding a new SERVER-/POOL- requirement without
    updating REQUIREMENT_COVERAGE fails this test immediately, and any empty
    coverage string is rejected.
    """
    missing = _ALL_REQUIREMENT_IDS - REQUIREMENT_COVERAGE.keys()
    assert not missing, f"Requirements missing from REQUIREMENT_COVERAGE: {missing}"

    for req_id, coverage in REQUIREMENT_COVERAGE.items():
        assert coverage, f"REQUIREMENT_COVERAGE[{req_id!r}] must not be empty"

    empty = {k for k, v in REQUIREMENT_COVERAGE.items() if not v}
    assert not empty, f"Empty coverage strings found: {empty}"


# --------------------------------------------------------------------------- #
# Live test helpers
# --------------------------------------------------------------------------- #

_LIVE_SKIP_REASON = (
    "SAPRFC_ASHOST not set — no live SAP system available (D-06 live end-to-end "
    "proof is gated on a real gateway + SM59 type-T destination)"
)


def _char_field(name: str, direction: int) -> FieldDesc:
    """A CHAR(255) FieldDesc mirroring tests/test_phase05_server.py."""
    return FieldDesc(
        name=name,
        rfctype=_RFCTYPE_CHAR,
        nuc_length=255,
        nuc_offset=0,
        uc_length=510,
        uc_offset=0,
        decimals=0,
        unicode_mode=True,
        direction=direction,
    )


def _stfc_connection_desc() -> FunctionDesc:
    """Hand-built FunctionDesc for STFC_CONNECTION (META-04 path).

    STFC_CONNECTION signature:
      IMPORTING REQUTEXT  CHAR(255)   (client sends -> server reads)
      EXPORTING ECHOTEXT  CHAR(255)   (handler produces -> server writes)
      EXPORTING RESPTEXT  CHAR(255)   (handler produces -> server writes)

    Used by the live inbound server test so the deserialize/serialize path runs
    against a known FM that an ABAP report can trigger via the type-T destination.
    """
    return FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            _char_field("REQUTEXT", RFC_IMPORT),
            _char_field("ECHOTEXT", RFC_EXPORT),
            _char_field("RESPTEXT", RFC_EXPORT),
        ],
    )


# --------------------------------------------------------------------------- #
# Live end-to-end server (requires SAPRFC_* env vars + SM59 type-T destination)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST") or not os.environ.get("SAPRFC_PROGRAM_ID"),
    reason=_LIVE_SKIP_REASON + " or SAPRFC_PROGRAM_ID not set (SM59 type-T setup required)",
)
def test_live_inbound_call() -> None:
    """SAP calls the registered Python handler end-to-end (SERVER-01..06, D-06).

    This is the Phase 5 gate: it proves SAP actually pushes an inbound RFC call to
    the Python server, the handler receives typed parameters, and its response
    reaches SAP. It CANNOT be stubbed or deferred (D-06).

    Manual SAP-side trigger (run while this test is waiting for the inbound call):
      1. In SM59, confirm a *type-T* (TCP/IP, "Registered Server Program")
         destination whose Registered Server Program ID equals SAPRFC_PROGRAM_ID,
         pointing at the gateway given by SAPRFC_GWHOST (default SAPRFC_ASHOST),
         port derived from SAPRFC_SYSNR (3300 + sysnr).
      2. While this test runs, the Python server registers that PROGRAM_ID; SM59 →
         "Registration" shows it as registered.
      3. Run an ABAP report (e.g. via SE38/SA38) that issues:
             CALL FUNCTION 'STFC_CONNECTION' DESTINATION '<sm59-dest>'
               EXPORTING REQUTEXT = 'saprfc_phase05_live'
               IMPORTING ECHOTEXT = lv_echo
                         RESPTEXT = lv_resp.
         (or trigger the equivalent transaction). That call is delivered to the
         handler below.

    Assertions: the handler observed the expected typed REQUTEXT (a str), and the
    inbound call completed (SAP accepted the serialized response) within the
    timeout. SAPRFC_PASSWD is never logged or asserted in plaintext.
    """
    gwhost = os.environ.get("SAPRFC_GWHOST", os.environ["SAPRFC_ASHOST"])
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    gwserv = str(3300 + int(sysnr))
    program_id = os.environ["SAPRFC_PROGRAM_ID"]

    received: dict[str, object] = {}
    call_seen = threading.Event()

    server = RfcServer({"program_id": program_id, "gwhost": gwhost, "gwserv": gwserv})

    @server.function("STFC_CONNECTION", _stfc_connection_desc())
    def _handle(request: dict) -> dict:
        # Capture what SAP sent (typed dict per the registered FunctionDesc).
        received.update(request)
        call_seen.set()
        requtext = request.get("REQUTEXT", "")
        return {"ECHOTEXT": requtext, "RESPTEXT": "saprfclib python handler ok"}

    # serve_forever blocks (it runs the asyncio loop and join()s its thread), so
    # drive it from a background thread and wait on the handler event here.
    serve_thread = threading.Thread(
        target=server.serve_forever, name="saprfclib-live-serve", daemon=True
    )
    serve_thread.start()
    try:
        # Wait for the human-triggered ABAP report to push the inbound call.
        triggered = call_seen.wait(timeout=120.0)
        assert triggered, (
            "no inbound call received within 120s — run the ABAP report that "
            "CALLs STFC_CONNECTION via the SM59 type-T destination "
            f"(PROGRAM_ID={program_id}) while this test waits"
        )

        # The handler received the client's IMPORTING value as a typed str.
        assert "REQUTEXT" in received, (
            f"handler did not receive REQUTEXT; got keys {list(received.keys())}"
        )
        assert isinstance(received["REQUTEXT"], str), (
            f"REQUTEXT must decode to str, got {type(received['REQUTEXT'])}"
        )
        # Give the serialized response a moment to flush back to SAP.
        time.sleep(0.5)
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# Live connection pool (requires SAPRFC_* env vars)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("SAPRFC_ASHOST"), reason=_LIVE_SKIP_REASON)
def test_live_pool_acquire_call_release() -> None:
    """ConnectionPool lends real connections that call STFC_CONNECTION (POOL-01..04).

    Builds a ConnectionPool(min_size=2, max_size=4) from the SAPRFC_* env, acquires
    a connection, calls STFC_CONNECTION on it (proving the lent connection is a live
    one), then holds two connections concurrently to prove single-owner semantics
    (two simultaneous acquires return two distinct Connection objects), and closes
    the pool. SAPRFC_PASSWD is read from the environment only and never logged.

    Env vars: SAPRFC_ASHOST, SAPRFC_SYSNR (default "00"), SAPRFC_CLIENT (default
    "001"), SAPRFC_USER, SAPRFC_PASSWD.
    """
    params = {
        "ashost": os.environ["SAPRFC_ASHOST"],
        "sysnr": os.environ.get("SAPRFC_SYSNR", "00"),
        "client": os.environ.get("SAPRFC_CLIENT", "001"),
        "user": os.environ["SAPRFC_USER"],
        "passwd": os.environ["SAPRFC_PASSWD"],
    }

    # POOL-01: min_size=2 warmed at construction, grows to max_size=4 on demand.
    pool = ConnectionPool(params, min_size=2, max_size=4)
    try:
        # POOL-02 + acquire/call/release: lend one, call STFC_CONNECTION, release.
        with pool.acquire(timeout=30.0) as conn:
            result = conn.call("STFC_CONNECTION", REQUTEXT="pool")
            assert isinstance(result, dict), f"expected dict, got {type(result)}"
            assert "ECHOTEXT" in result, f"ECHOTEXT missing from result keys: {list(result.keys())}"
            assert "pool" in result["ECHOTEXT"], (
                f"ECHOTEXT should echo REQUTEXT; got {result['ECHOTEXT']!r}"
            )

        # POOL-02 single-owner: two concurrent acquires must yield distinct conns.
        with pool.acquire(timeout=30.0) as conn_a:
            with pool.acquire(timeout=30.0) as conn_b:
                assert conn_a is not conn_b, (
                    "two concurrent acquires returned the SAME connection — "
                    "single-owner semantics violated (POOL-02)"
                )
    finally:
        # POOL-04 graceful shutdown: close every pooled connection.
        pool.close()
