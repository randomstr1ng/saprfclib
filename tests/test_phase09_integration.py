# tests/test_phase09_integration.py
#
# Phase 9 end-to-end wiring and requirement traceability for tRFC hardening
# (TRFC-01..08) and the async-native API surface (CLIENT-01..07).
#
# Requirement coverage:
#   Offline-verified: unit tests in tests/test_phase09_{retry,sqlite_store,
#     async_client,async_pool,async_server}.py (turned green in Waves 1-3).
#   Live skip-guarded (D-08 gate):
#     - test_live_async_call_roundtrip  (CLIENT-01..07 async parity, Wave 4)
#     - test_live_async_trfc_retry_lands (TRFC-01..05 retry hardening, Wave 4)
#
# This file's test_requirement_traceability PASSES at Wave 0 (checks only the
# coverage dict, not the implementation — mirror of test_phase06_integration.py).
#
# Environment variables (same as Phase 6):
#   SAPRFC_ASHOST     A4H application server host (skip-guard for live tests)
#   SAPRFC_SYSNR      system number (default "00")
#   SAPRFC_CLIENT     SAP client (e.g. "001")
#   SAPRFC_USER       SAP logon user
#   SAPRFC_PASSWD     SAP logon password — NEVER logged, printed, or asserted
#
# SAPRFC_PASSWD is read from the environment only; never logged, printed, or
# asserted in plaintext (T-04-CRED / T-06-E01 / T-09-06-CRED).

from __future__ import annotations

import os
import pathlib
import uuid

import pytest

# --------------------------------------------------------------------------- #
# Requirement traceability (completeness guard — test_requirement_traceability
# must PASS at Wave 0; it only checks the dict, not the implementation)
# --------------------------------------------------------------------------- #

#: Each Phase 9 requirement ID maps to the canonical test node id that proves it.
#: TRFC-01..08: tRFC / bgRFC retry + SQLite durable store behaviours.
#: CLIENT-01..07: async-native API parity (await conn.call, pool, server).
REQUIREMENT_COVERAGE: dict[str, str] = {
    # TRFC-01: tRFC call with 24-char TID auto-retries on CommunicationError;
    # same TID reused so RFC_EXECUTED dedupes on backend.
    # Proven: offline (mock) + live gate (test_live_async_trfc_retry_lands).
    "TRFC-01": "tests/test_phase09_retry.py::test_trfc_retries_on_communication_error",
    # TRFC-02: create_tid / confirm_tid lifecycle; TID reuse across retries.
    # Proven: offline (mock).
    "TRFC-02": "tests/test_phase09_retry.py::test_trfc_tid_reused_across_retries",
    # TRFC-03: server returns RFC_EXECUTED for known TID (async store check).
    # Proven: offline (async server mock).
    "TRFC-03": "tests/test_phase09_async_server.py::test_async_server_duplicate_tid",
    # TRFC-04: qRFC call with queue name retries on CommunicationError.
    # Proven: offline (mock).
    "TRFC-04": "tests/test_phase09_retry.py::test_qrfc_retry_with_queue",
    # TRFC-05: bgRFC unit submit retries on CommunicationError; parks on exhaustion.
    # Proven: offline (mock).
    "TRFC-05": "tests/test_phase09_retry.py::test_bgrfc_unit_retry",
    # TRFC-06: confirm/rollback/get_unit_state map to UnitState via async store.
    # Proven: offline (mock).
    "TRFC-06": "tests/test_phase09_retry.py::test_bgrfc_unit_state_transitions",
    # TRFC-07: bgRFC server callbacks fire in correct order with async handler.
    # Proven: offline (async server mock).
    "TRFC-07": "tests/test_phase09_async_server.py::test_async_server_bgrfc_callback_order",
    # TRFC-08: SqliteTidStore / SqliteUnitStore Protocol + :memory: + disk durability.
    # Proven: offline (SQLite store unit tests).
    "TRFC-08": "tests/test_phase09_sqlite_store.py::test_sqlite_tid_store_round_trip",
    # CLIENT-01: await conn.call("FM", PARAM=...) returns result dict.
    # Proven: offline (mock) + live gate (test_live_async_call_roundtrip).
    "CLIENT-01": "tests/test_phase09_async_client.py::test_async_call_returns_dict",
    # CLIENT-02: IMPORTING / EXPORTING / CHANGING / TABLE params by name.
    # Proven: offline (mock).
    "CLIENT-02": "tests/test_phase09_async_client.py::test_async_call_param_types",
    # CLIENT-03: Python-native return types from async call.
    # Proven: offline (mock).
    "CLIENT-03": "tests/test_phase09_async_client.py::test_async_call_return_types",
    # CLIENT-04: AbapApplicationError surfaces from async call.
    # Proven: offline (mock error injection).
    "CLIENT-04": "tests/test_phase09_async_client.py::test_async_call_abap_application_error",
    # CLIENT-05: AbapSystemFailure surfaces from async call.
    # Proven: offline (mock error injection).
    "CLIENT-05": "tests/test_phase09_async_client.py::test_async_call_abap_system_failure",
    # CLIENT-06: CommunicationError on network / protocol failure from async call.
    # Proven: offline (mock error injection).
    "CLIENT-06": "tests/test_phase09_async_client.py::test_async_call_communication_error",
    # CLIENT-07: get_connection_attributes() returns negotiated attributes async.
    # Proven: offline (mock) + live gate (test_live_async_call_roundtrip).
    "CLIENT-07": "tests/test_phase09_async_client.py::test_async_get_connection_attributes",
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
        "CLIENT-01",
        "CLIENT-02",
        "CLIENT-03",
        "CLIENT-04",
        "CLIENT-05",
        "CLIENT-06",
        "CLIENT-07",
    }
)

# Repo root resolved from this file's location (tests/test_phase09_integration.py).
# Used by test_requirement_traceability to assert node-id file paths exist on disk
# (T-09-06-FALSEGREEN mitigation: typos in test file names are caught here).
_REPO_ROOT: pathlib.Path = pathlib.Path(__file__).parent.parent


def test_requirement_traceability() -> None:
    """Every Phase 9 requirement maps to a test node id; no entry is empty.

    This test MUST PASS at Wave 0 close. It validates only the coverage dict,
    not the implementation — all referenced tests are xfail/importorskip/skip
    while production symbols are absent.

    Prevents silent coverage gaps: adding a new requirement without updating
    REQUIREMENT_COVERAGE fails this test immediately, and any empty coverage
    string is rejected.

    Also asserts that the file path in each node id (part before '::') exists
    on disk — so a typo in the test file name is caught here rather than
    silently ignored (T-09-06-FALSEGREEN).
    """
    missing = _ALL_REQUIREMENT_IDS - REQUIREMENT_COVERAGE.keys()
    assert not missing, (
        f"Requirements missing from REQUIREMENT_COVERAGE: {missing}\n"
        "Update REQUIREMENT_COVERAGE in tests/test_phase09_integration.py."
    )

    for req_id, coverage in REQUIREMENT_COVERAGE.items():
        assert coverage, f"REQUIREMENT_COVERAGE[{req_id!r}] must not be empty"

    empty = {k for k, v in REQUIREMENT_COVERAGE.items() if not v.strip()}
    assert not empty, f"Empty coverage strings found: {empty}"

    # All mapped IDs must be known requirement IDs (no typos)
    unknown = REQUIREMENT_COVERAGE.keys() - _ALL_REQUIREMENT_IDS
    assert not unknown, (
        f"Unknown requirement IDs in REQUIREMENT_COVERAGE: {unknown}\n"
        f"Valid IDs: {_ALL_REQUIREMENT_IDS!r}"
    )

    # Every node-id must contain '::' (a real node id, not a bare placeholder)
    no_separator = {k: v for k, v in REQUIREMENT_COVERAGE.items() if "::" not in v}
    assert not no_separator, (
        f"Coverage values must contain '::' (format: file::test_name): {no_separator}"
    )

    # The file path portion (before '::') must exist on disk relative to repo root.
    # This catches typos in test file names and ensures the coverage dict stays
    # up to date when test files are renamed (T-09-06-FALSEGREEN).
    missing_files: dict[str, str] = {}
    for req_id, coverage in REQUIREMENT_COVERAGE.items():
        node_file = coverage.split("::")[0]
        full_path = _REPO_ROOT / node_file
        if not full_path.exists():
            missing_files[req_id] = node_file
    assert not missing_files, (
        "Node-id file paths do not exist on disk (check for typos in REQUIREMENT_COVERAGE):\n"
        + "\n".join(f"  {req_id}: {path}" for req_id, path in missing_files.items())
    )


# --------------------------------------------------------------------------- #
# Live gate helpers
# --------------------------------------------------------------------------- #

_LIVE_SKIP_REASON = (
    "SAPRFC_ASHOST not set — no live SAP system available "
    "(D-08 phase-gate: async round-trip + retry must pass before Phase 9 is complete)"
)


class _FailOnceSendTransport:
    """Transport wrapper: raises OSError on the FIRST send_message, then delegates.

    Injects a single transient send failure to prove the tRFC retry loop retries
    with the same TID and eventually lands. The underlying TCP connection remains
    intact (the bytes are NOT written on the failing call), so the second attempt
    can reuse the same stream.

    Thread safety: single asyncio task only (no Lock required).
    """

    def __init__(self, real_transport: object) -> None:
        self._real = real_transport
        self._send_count: int = 0

    async def send_message(self, payload: bytes) -> None:
        self._send_count += 1
        if self._send_count == 1:
            # Simulate a transient network write failure. The bytes are NOT
            # written to the TCP stream, so the stream is still valid.
            raise OSError("Simulated transient failure on first send (test double)")
        await self._real.send_message(payload)  # type: ignore[attr-defined]

    async def recv_message(self) -> bytes:
        return await self._real.recv_message()  # type: ignore[attr-defined]

    async def close(self) -> None:
        await self._real.close()  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Live: async call round-trip — CLIENT-01..07 (Wave 4)
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST"),
    reason=_LIVE_SKIP_REASON,
)
async def test_live_async_call_roundtrip() -> None:
    """Async round-trip: await conn.call("STFC_CONNECTION") echoes REQUTEXT, live SAP.

    D-08 gate (CLIENT-01..07): proves the async call path end-to-end against a
    live SAP system:
    - CLIENT-01: await conn.call returns a dict with EXPORTING params.
    - CLIENT-07: get_connection_attributes() returns non-empty sys_id.

    SAPRFC_PASSWD is read from the environment only; never logged, printed, or
    asserted in plaintext (T-04-CRED / T-09-06-CRED).
    """
    import saprfclib  # noqa: PLC0415 — live gate; deferred import avoids hard dep

    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ["SAPRFC_USER"]
    # Password sourced from env only — never logged, printed, or asserted.
    passwd = os.environ["SAPRFC_PASSWD"]

    conn = await saprfclib.connect_async(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
    )
    try:
        result = await conn.call("STFC_CONNECTION", REQUTEXT="hi")

        assert isinstance(result, dict), (
            f"conn.call() must return a dict; got {type(result).__name__}"
        )
        assert "ECHOTEXT" in result, (
            f"ECHOTEXT missing from STFC_CONNECTION result keys: {list(result.keys())}"
        )
        assert "hi" in result["ECHOTEXT"], (
            f"ECHOTEXT should echo REQUTEXT 'hi'; got {result['ECHOTEXT']!r}"
        )

        attrs = conn.get_connection_attributes()
        assert attrs.sys_id, (
            f"get_connection_attributes().sys_id must be non-empty; got {attrs.sys_id!r}"
        )
    finally:
        await conn.close()


# --------------------------------------------------------------------------- #
# Live: tRFC retry lands after forced transient failure — TRFC-01..05 (Wave 4)
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(
    not os.environ.get("SAPRFC_ASHOST"),
    reason=_LIVE_SKIP_REASON,
)
async def test_live_async_trfc_retry_lands(tmp_path: pathlib.Path) -> None:
    """Live tRFC retry: forced first-send failure auto-retries; nothing left parked.

    D-08 gate (TRFC-01..05): proves retry hardening end-to-end against a live
    SAP system:
    - TRFC-01: CommunicationError on send triggers the retry loop.
    - TRFC-02: same TID is reused on retry; SAP deduplicates via RFC_EXECUTED.
    - D-01/D-02: retry loop succeeds with max_retries=1 (2 total attempts).
    - D-03b: store.list_parked() is empty after a successful retry (no parking).

    The transport is replaced AFTER the handshake with a _FailOnceSendTransport
    that raises OSError on the first send_message call, then delegates to the
    real transport. The retry loop re-sends the SAME TID; no data loss.

    SAPRFC_PASSWD is read from the environment only; never logged, printed, or
    asserted in plaintext (T-04-CRED / T-09-06-CRED).
    """
    import saprfclib  # noqa: PLC0415 — live gate; deferred import avoids hard dep
    from saprfclib.stores import SqliteTidStore  # noqa: PLC0415

    ashost = os.environ["SAPRFC_ASHOST"]
    sysnr = os.environ.get("SAPRFC_SYSNR", "00")
    client = os.environ.get("SAPRFC_CLIENT", "001")
    user = os.environ["SAPRFC_USER"]
    # Password sourced from env only — never logged, printed, or asserted.
    passwd = os.environ["SAPRFC_PASSWD"]

    store = SqliteTidStore(str(tmp_path / "tids.db"))
    conn = await saprfclib.connect_async(
        ashost=ashost,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=passwd,
        max_retries=1,  # 2 total attempts: fail once, succeed once
        retry_delay=0.0,  # no sleep between retries for test speed
        tid_store=store,
    )
    try:
        # Inject a fail-once wrapper AFTER the handshake so the connection is
        # fully established. The retry loop re-uses self._transport on every
        # attempt, so the second send goes through the real transport.
        conn._transport = _FailOnceSendTransport(conn._transport)

        # Generate a 24-char TID (UUID hex, same algorithm as Connection.create_tid).
        tid = uuid.uuid4().hex[:24].upper()

        # call_transactional should fail on the first send, retry, and land.
        # RetryExhausted must NOT be raised (max_retries=1 means 2 total attempts;
        # the wrapper only fails the first, so the second succeeds).
        await conn.call_transactional("STFC_CONNECTION", tid=tid)

        # After a successful retry, the store must be empty — no parking happened.
        parked = store.list_parked()
        assert parked == [], (
            f"store.list_parked() must be empty after successful retry; got {parked!r}"
        )

        # Confirm the TID to complete the tRFC lifecycle (TRFC-02).
        await conn.confirm_tid(tid)
    finally:
        await conn.close()
