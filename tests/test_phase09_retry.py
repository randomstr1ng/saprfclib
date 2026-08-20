# tests/test_phase09_retry.py
#
# Phase 9 offline tests: tRFC/qRFC/bgRFC retry + park + RetryExhausted.
#
# All test bodies use AsyncMockTransport or direct _submit_with_retry calls
# to exercise the retry loop offline (no live SAP system required).
#
# Coverage:
#   TRFC-01/02/04/05/06 — retry loop, TID reuse, qRFC queue, bgRFC unit, state
#
# Acceptance criteria validated here (offline, no live SAP system required):
#   - CommunicationError triggers retry (D-01); backoff sequence 1s/2s/4s (D-02)
#   - RetryExhausted carries .tid and .cause; NO passwd/payload attr (D-03/T-06)
#   - AbapApplicationError is NOT retried (Pitfall 4)
#   - Park-on-exhaustion stores the payload (D-03b)

from __future__ import annotations

import asyncio

import pytest

saprfc_connection = pytest.importorskip(
    "saprfclib.connection",
    reason="saprfclib.connection not importable — skipping Phase 9 retry tests",
)

from saprfclib.connection import AsyncConnection  # noqa: E402
from saprfclib.exceptions import (  # noqa: E402
    AbapApplicationError,
    CommunicationError,
    RetryExhausted,
)
from saprfclib.session import SessionState  # noqa: E402
from saprfclib.stores import InMemoryTidStore, UnitState  # noqa: E402
from tests._mocks import AsyncMockTransport  # noqa: E402

# --------------------------------------------------------------------------- #
# Module-level helper: _FailNThenOkTransport
# --------------------------------------------------------------------------- #


class _FailNThenOkTransport:
    """Async transport double that raises EOFError the first n_fails times
    recv_message is called, then returns ok_bytes thereafter.

    send_message always appends the payload to `sent` without failing.
    """

    def __init__(self, n_fails: int, ok_bytes: bytes = b"") -> None:
        self.sent: list[bytes] = []
        self._n_fails = n_fails
        self._ok_bytes = ok_bytes
        self._call_count = 0

    async def send_message(self, payload: bytes) -> None:
        self.sent.append(bytes(payload))

    async def recv_message(self) -> bytes:
        self._call_count += 1
        if self._call_count <= self._n_fails:
            raise EOFError("injected failure")
        return self._ok_bytes

    async def close(self) -> None:
        pass


# --------------------------------------------------------------------------- #
# Module-level helper: _make_async_conn
# --------------------------------------------------------------------------- #


def _make_async_conn(
    *,
    max_retries: int = 0,
    retry_delay: float = 0.0,
    tid_store: object = None,
    unit_store: object = None,
    responses: list[bytes] | None = None,
) -> tuple[AsyncConnection, AsyncMockTransport]:
    """Create AsyncConnection with AsyncMockTransport for offline retry tests.

    Does NOT set session state — _submit_with_retry does not require READY.
    """
    transport = AsyncMockTransport(responses or [])
    conn = AsyncConnection(
        transport,
        max_retries=max_retries,
        retry_delay=retry_delay,
        tid_store=tid_store,
        unit_store=unit_store,
    )
    return conn, transport


# --------------------------------------------------------------------------- #
# TRFC-01/02: tRFC auto-retry on CommunicationError + TID reuse
# --------------------------------------------------------------------------- #


async def test_trfc_retries_on_communication_error() -> None:
    """TRFC-01: _submit_with_retry retries on CommunicationError K times, then succeeds.

    Asserts:
    - The factory is called exactly max_retries+1 times (K failures + 1 success).
    - No exception is raised when the last attempt succeeds.
    """
    conn, _ = _make_async_conn(max_retries=2, retry_delay=0.0)
    call_count = 0

    async def factory() -> None:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise CommunicationError("transient")
        return None

    await conn._submit_with_retry(
        tid="A" * 24,
        request_bytes=b"req",
        send_coro_factory=factory,
        max_retries=2,
        retry_delay=0.0,
    )
    assert call_count == 3


async def test_trfc_tid_reused_across_retries() -> None:
    """TRFC-02: the same 24-char TID is reused for every retry attempt.

    The tRFC exactly-once guarantee relies on the backend deduping by TID.
    A new TID on each retry would defeat the RFC_EXECUTED guard.

    Asserts:
    - All retry send_message calls include the same request bytes.
    - The TID bytes (UTF-16LE) appear in the first sent frame.
    - Three send attempts occur (2 failures + 1 success).
    """
    transport = _FailNThenOkTransport(n_fails=2, ok_bytes=b"")
    conn = AsyncConnection(transport, max_retries=2, retry_delay=0.0)
    # Force session to READY so call_transactional can proceed
    conn._session._state = SessionState.READY
    tid = "ABCDEF1234567890ABCDEF12"  # 24 chars, RFC alphabet
    await conn.call_transactional("STFC_CONNECTION", tid=tid)
    # call_transactional sends request each retry attempt; recv_message fails first 2
    assert len(transport.sent) == 3
    assert tid.encode("utf-16-le") in transport.sent[0]
    assert transport.sent[0] == transport.sent[1] == transport.sent[2]


# --------------------------------------------------------------------------- #
# TRFC-04: qRFC with explicit queue name retries on CommunicationError
# --------------------------------------------------------------------------- #


async def test_qrfc_retry_with_queue() -> None:
    """TRFC-04: call_transactional with queue= retries on CommunicationError.

    qRFC frames carry the ARFCQUEUE param alongside the TID. Retry must
    preserve the queue name across all attempts.

    Asserts:
    - Retry succeeds after 1 CommunicationError failure.
    - Both retry frames include the ARFCQUEUE parameter (queue name in UTF-16LE).
    - The two sent frames are identical (same request bytes, same queue).
    """
    transport = _FailNThenOkTransport(n_fails=1, ok_bytes=b"")
    conn = AsyncConnection(transport, max_retries=1, retry_delay=0.0)
    conn._session._state = SessionState.READY
    tid = "ABCDEF1234567890ABCDEF12"
    queue = "TESTQUEUE"
    await conn.call_transactional("STFC_CONNECTION", tid=tid, queue=queue)
    assert len(transport.sent) == 2
    assert queue.encode("utf-16-le") in transport.sent[0]
    assert transport.sent[0] == transport.sent[1]


# --------------------------------------------------------------------------- #
# TRFC-01/02: RetryExhausted raised + payload parked after max_retries
# --------------------------------------------------------------------------- #


async def test_trfc_retry_exhausted_raises_retry_exhausted() -> None:
    """TRFC-01: after max_retries failures, RetryExhausted is raised.

    RetryExhausted must carry:
    - .tid: the 24-char TID used for all attempts.
    - .cause: the last CommunicationError.
    - NO .passwd attribute (T-06-E01 / D-03 — credentials must not leak).
    - NO .payload attribute (D-03 — caller reads store).

    Asserts:
    - RetryExhausted is raised after exactly max_retries+1 attempts.
    - .tid matches the passed TID.
    - .cause is a CommunicationError instance.
    """
    conn, _ = _make_async_conn(max_retries=2, retry_delay=0.0)
    tid = "CCCCCCCCCCCCCCCCCCCCCCCC"

    async def always_fail() -> None:
        raise CommunicationError("network down")

    with pytest.raises(RetryExhausted) as exc_info:
        await conn._submit_with_retry(
            tid=tid,
            request_bytes=b"req",
            send_coro_factory=always_fail,
            max_retries=2,
            retry_delay=0.0,
        )
    assert exc_info.value.tid == tid
    assert isinstance(exc_info.value.cause, CommunicationError)
    assert not hasattr(exc_info.value, "passwd")
    assert not hasattr(exc_info.value, "payload")


async def test_retry_exhausted_parks_payload_in_store() -> None:
    """TRFC-01 / D-03b: on RetryExhausted, payload is parked in the durable store.

    After max_retries, the pending call bytes must be persisted via
    store.park(tid, payload_bytes) so the caller can re-drive via
    conn.retry_parked(tid) without re-marshaling.

    Asserts:
    - store.get_parked(tid) returns non-empty bytes after RetryExhausted.
    - store.list_parked() includes the TID.
    """
    store = InMemoryTidStore()
    conn, _ = _make_async_conn(max_retries=1, retry_delay=0.0, tid_store=store)
    tid = "DDDDDDDDDDDDDDDDDDDDDDDD"
    payload = b"serialised_request_bytes"

    async def always_fail() -> None:
        raise CommunicationError("fail")

    with pytest.raises(RetryExhausted):
        await conn._submit_with_retry(
            tid=tid,
            request_bytes=payload,
            send_coro_factory=always_fail,
            max_retries=1,
            retry_delay=0.0,
        )
    assert store.get_parked(tid) == payload
    assert tid in store.list_parked()


# --------------------------------------------------------------------------- #
# TRFC-01: AbapApplicationError is NOT retried (Pitfall 4 guard)
# --------------------------------------------------------------------------- #


async def test_abap_application_error_not_retried() -> None:
    """TRFC-01 / Pitfall 4: AbapApplicationError propagates immediately, not retried.

    AbapApplicationError is a deterministic backend outcome, not a transient
    network failure. Retrying it would re-execute non-idempotent ABAP logic.

    Asserts:
    - When the factory yields an AbapApplicationError, the retry loop does NOT retry
      (attempt count == 1).
    - AbapApplicationError propagates to the caller unmodified.
    """
    conn, _ = _make_async_conn(max_retries=3, retry_delay=0.0)
    call_count = 0

    async def factory() -> None:
        nonlocal call_count
        call_count += 1
        raise AbapApplicationError(key="TEST_ERR", message="deterministic")

    with pytest.raises(AbapApplicationError) as exc_info:
        await conn._submit_with_retry(
            tid="E" * 24,
            request_bytes=b"req",
            send_coro_factory=factory,
            max_retries=3,
            retry_delay=0.0,
        )
    assert call_count == 1
    assert exc_info.value.key == "TEST_ERR"


# --------------------------------------------------------------------------- #
# D-02: backoff delay sequence 1s / 2s / 4s
# --------------------------------------------------------------------------- #


async def test_retry_backoff_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    """D-02: exponential backoff delays are 1s, 2s, 4s (base delays, ±10% jitter).

    The retry loop calls asyncio.sleep() between attempts. The base sequence
    must be 1s * 2^0, 1s * 2^1, 1s * 2^2 (i.e. 1s, 2s, 4s) — configurable
    via retry_delay kwarg, default 1.0.

    Monkeypatches asyncio.sleep to capture the sequence without real waiting.

    Asserts:
    - len(sleep_calls) == max_retries (one sleep per retry, none on first attempt).
    - sleep_calls[i] is approximately retry_delay * (2 ** i) within ±15% jitter.
    """
    sleep_calls: list[float] = []

    async def mock_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    monkeypatch.setattr(asyncio, "sleep", mock_sleep)

    conn, _ = _make_async_conn(max_retries=3, retry_delay=1.0)

    async def always_fail() -> None:
        raise CommunicationError("fail")

    with pytest.raises(RetryExhausted):
        await conn._submit_with_retry(
            tid="F" * 24,
            request_bytes=b"req",
            send_coro_factory=always_fail,
            max_retries=3,
            retry_delay=1.0,
        )

    assert len(sleep_calls) == 3
    assert sleep_calls[0] == pytest.approx(1.0, rel=0.15)
    assert sleep_calls[1] == pytest.approx(2.0, rel=0.15)
    assert sleep_calls[2] == pytest.approx(4.0, rel=0.15)


# --------------------------------------------------------------------------- #
# TRFC-05: bgRFC unit submit retries on CommunicationError
# --------------------------------------------------------------------------- #


async def test_bgrfc_unit_retry() -> None:
    """TRFC-05: bgRFC unit submit retries on CommunicationError, parks on exhaustion.

    The bgRFC submit (_submit_unit) must be wrapped in the same retry loop as
    tRFC call_transactional. On exhaustion a RetryExhausted carrying .unit_id
    is raised.

    Phase A: factory fails once then succeeds — assert call_count == 2.
    Phase B: always_fail factory — assert RetryExhausted with .unit_id and .cause.
    """
    unit_id = "1234567890ABCDEF1234567890ABCDEF"  # 32 uppercase hex chars

    # Phase A: succeed after one failure
    conn_a, _ = _make_async_conn(max_retries=1, retry_delay=0.0)
    call_count = 0

    async def fail_once() -> None:
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise CommunicationError("transient")
        return None

    await conn_a._submit_with_retry(
        unit_id=unit_id,
        unit_type="T",
        request_bytes=b"unit_req",
        send_coro_factory=fail_once,
        max_retries=1,
        retry_delay=0.0,
    )
    assert call_count == 2

    # Phase B: always fails → RetryExhausted with .unit_id
    conn_b, _ = _make_async_conn(max_retries=1, retry_delay=0.0)

    async def always_fail() -> None:
        raise CommunicationError("network down")

    with pytest.raises(RetryExhausted) as exc_info:
        await conn_b._submit_with_retry(
            unit_id=unit_id,
            unit_type="T",
            request_bytes=b"unit_req",
            send_coro_factory=always_fail,
            max_retries=1,
            retry_delay=0.0,
        )
    assert exc_info.value.unit_id == unit_id
    assert isinstance(exc_info.value.cause, CommunicationError)


# --------------------------------------------------------------------------- #
# TRFC-06: bgRFC unit state transitions via async store
# --------------------------------------------------------------------------- #


async def test_bgrfc_unit_state_transitions() -> None:
    """TRFC-06: confirm/rollback/get_unit_state use the async seam correctly.

    Uses AsyncMockTransport with 3 scripted responses (one per operation).
    Asserts:
    - get_unit_state() returns UnitState.NOT_FOUND for empty response.
    - confirm_unit() completes without error.
    - rollback_unit() completes without error.
    """
    transport = AsyncMockTransport(responses=[b"", b"ok", b""])
    conn = AsyncConnection(transport)
    conn._session._state = SessionState.READY
    unit_id = "1234567890ABCDEF1234567890ABCDEF"

    state = await conn.get_unit_state(unit_id, unit_type="T")
    assert isinstance(state, UnitState)
    assert state == UnitState.NOT_FOUND

    # confirm_unit: must not raise
    await conn.confirm_unit(unit_id, unit_type="T")

    # rollback_unit: must not raise
    await conn.rollback_unit(unit_id, unit_type="T")
