# tests/test_phase09_async_pool.py
#
# Phase 9 offline tests: AsyncConnectionPool (D-08 / async pool parity).
#
# asyncio_mode="auto" so bare async def test_* run without decorators.
#
# Coverage:
#   - async with pool.acquire() as conn: single-owner lend
#   - asyncio.Condition-bounded concurrency (max_size honored under gathered acquires)
#   - Broken-connection discard (a conn whose async ping fails is not re-lent)

from __future__ import annotations

import asyncio
import unittest.mock as mock

import pytest

saprfc_pool = pytest.importorskip(
    "saprfclib.pool",
    reason="saprfclib.pool not importable — skipping Phase 9 async pool tests",
)

from saprfclib.pool import AsyncConnectionPool  # noqa: E402

# Minimal params dict for pool construction — no real connection is made
# since _open is always patched in these tests.
_POOL_PARAMS: dict = {
    "ashost": "testhost",
    "sysnr": 0,
    "client": "100",
    "user": "TEST",
    "passwd": "TEST",
}


# --------------------------------------------------------------------------- #
# Single-owner lend: async with pool.acquire() as conn
# --------------------------------------------------------------------------- #


async def test_async_pool_acquire_single_lend() -> None:
    """Async pool lends exactly one connection via `async with pool.acquire()`.

    The pool must implement the async context manager protocol: __aenter__
    returns a connection object, __aexit__ releases it back to the pool.

    Asserts:
    - conn is the object returned by fake_open.
    - Inside the block: conn is in pool._in_use.
    - After the block: conn is in pool._idle, not in pool._in_use.
    """
    pool = AsyncConnectionPool(_POOL_PARAMS, min_size=0, max_size=1)
    mock_conn = object()

    async def fake_open() -> object:
        return mock_conn

    pool._open = fake_open  # type: ignore[method-assign]
    pool._ping_ok = mock.AsyncMock(return_value=True)  # type: ignore[method-assign]

    async with pool.acquire(timeout=1.0) as conn:
        assert conn is mock_conn
        assert mock_conn in pool._in_use

    assert mock_conn in pool._idle
    assert mock_conn not in pool._in_use


# --------------------------------------------------------------------------- #
# Condition-bounded concurrency: max_size honored under gathered acquires
# --------------------------------------------------------------------------- #


async def test_async_pool_max_size_bounded() -> None:
    """AsyncConnectionPool(max_size=N) never lends more than N connections at once.

    Issues max_size concurrent acquire() calls. All N connections are lent.
    Asserts that N distinct connections are handed out and the pool never
    exceeded max_size.

    Asserts:
    - len(set(acquired)) == 2 (two distinct connections, no double-lending).
    - len(connections) <= 2 (pool never exceeded max_size).
    """
    pool = AsyncConnectionPool(_POOL_PARAMS, min_size=0, max_size=2)
    connections: list[object] = []
    acquired: list[object] = []

    async def fake_open() -> object:
        conn = object()
        connections.append(conn)
        return conn

    pool._open = fake_open  # type: ignore[method-assign]
    pool._ping_ok = mock.AsyncMock(return_value=True)  # type: ignore[method-assign]

    async def grab() -> None:
        async with pool.acquire(timeout=1.0) as conn:
            acquired.append(conn)
            await asyncio.sleep(0)

    await asyncio.gather(*[grab() for _ in range(2)])

    assert len({id(c) for c in acquired}) == 2
    assert len(connections) <= 2


# --------------------------------------------------------------------------- #
# Broken-connection discard: a failing ping is not re-lent
# --------------------------------------------------------------------------- #


async def test_async_pool_broken_connection_discarded() -> None:
    """A connection whose async ping fails is discarded; a fresh one is lent.

    When an AsyncConnection's ping (health check) returns False, the pool must
    discard that connection rather than returning it to the idle list. The next
    acquire() must lend a new, healthy connection.

    Asserts:
    - The acquired connection is the fresh one, not broken.
    - broken is not in pool._idle or pool._in_use after the acquire block.
    """
    pool = AsyncConnectionPool(_POOL_PARAMS, min_size=0, max_size=2)
    broken = object()
    fresh = object()

    # Pre-populate the idle deque with the broken connection
    async with pool._cond:
        pool._idle.append(broken)
        pool._created = 1

    open_calls: list[object] = []

    async def fake_open() -> object:
        open_calls.append(fresh)
        return fresh

    pool._open = fake_open  # type: ignore[method-assign]

    async def fake_ping(conn: object) -> bool:
        return conn is fresh

    pool._ping_ok = fake_ping  # type: ignore[method-assign]
    pool._safe_close = mock.AsyncMock()  # type: ignore[method-assign]

    async with pool.acquire(timeout=1.0) as conn:
        assert conn is fresh

    assert broken not in pool._idle
    assert broken not in pool._in_use
