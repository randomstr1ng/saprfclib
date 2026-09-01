# SPDX-License-Identifier: MPL-2.0
"""Pool error and shutdown paths.

These were the uncovered branches, and they are the ones where a fault does not
raise: a leaked slot shrinks the pool permanently until it deadlocks at
max_size, and a connection released into a closed pool leaks its socket. Neither
reports anything at the time.
"""

from __future__ import annotations

import threading

import pytest

from saprfclib import pool as pool_mod
from saprfclib.exceptions import PoolTimeoutError


class _Conn:
    def __init__(self) -> None:
        self.closed = False

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        self.closed = True


class _AsyncConn:
    def __init__(self) -> None:
        self.closed = False

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        self.closed = True


def _sync_pool(opener, max_size: int = 2) -> pool_mod.ConnectionPool:
    p = pool_mod.ConnectionPool.__new__(pool_mod.ConnectionPool)
    p.__init__({"ashost": "h"}, min_size=0, max_size=max_size)  # type: ignore[misc]
    p._open = opener  # type: ignore[method-assign]
    return p


def test_a_failed_open_does_not_leak_the_reservation() -> None:
    """The slot must come back, or the pool shrinks permanently.

    _checkout reserves a slot before opening, outside the lock. If the reservation
    is not undone when open() raises, the pool loses that slot for good and
    eventually deadlocks at max_size — reporting only a timeout, long after the
    open failures that caused it.
    """
    attempts = {"n": 0}

    def flaky() -> _Conn:
        attempts["n"] += 1
        raise OSError("connect refused")

    p = _sync_pool(flaky, max_size=2)
    for _ in range(5):
        with pytest.raises(OSError):
            with p.acquire(timeout=1.0):
                pass
    assert attempts["n"] == 5, "every attempt must reach the opener"
    assert p._created == 0, "a failed open must release its reservation"


def test_a_failed_open_wakes_a_waiter() -> None:
    """Otherwise a thread blocked on the pool waits out its whole timeout.

    The failure is already known; making everyone else wait for it turns one
    error into a stall across the caller's threads.
    """
    gate = threading.Event()

    def slow_failing() -> _Conn:
        gate.wait(timeout=2)
        raise OSError("refused")

    p = _sync_pool(slow_failing, max_size=1)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with p.acquire(timeout=3.0):
                pass
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    gate.set()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), "a waiter was not woken after the open failed"
    assert len(errors) == 2
    assert all(isinstance(e, (OSError, PoolTimeoutError)) for e in errors)


def test_release_into_a_closed_pool_closes_the_connection() -> None:
    """Returning it to a dead idle set would leak the socket silently."""
    conns: list[_Conn] = []

    def opener() -> _Conn:
        c = _Conn()
        conns.append(c)
        return c

    p = _sync_pool(opener, max_size=2)
    conn = p._checkout(timeout=1.0)
    p.close()
    p.release(conn)
    assert conn.closed, "a connection released after close() must be closed, not pooled"
    assert conn not in p._idle


def test_close_is_idempotent_and_closes_idle_connections() -> None:
    conns: list[_Conn] = []

    def opener() -> _Conn:
        c = _Conn()
        conns.append(c)
        return c

    p = _sync_pool(opener, max_size=2)
    with p.acquire(timeout=1.0):
        pass
    assert conns and not conns[0].closed
    p.close()
    assert conns[0].closed
    p.close()  # second call must not raise or double-close
    assert all(c.closed for c in conns)


def test_acquire_on_a_closed_pool_raises() -> None:
    """Better than handing out a connection from a pool that is shutting down."""
    p = _sync_pool(lambda: _Conn(), max_size=1)
    p.close()
    with pytest.raises(RuntimeError, match="closed"):
        with p.acquire(timeout=1.0):
            pass


@pytest.mark.asyncio
async def test_async_release_into_a_closed_pool_closes_the_connection() -> None:
    conns: list[_AsyncConn] = []

    async def opener() -> _AsyncConn:
        c = _AsyncConn()
        conns.append(c)
        return c

    p = pool_mod.AsyncConnectionPool({"ashost": "h"}, min_size=0, max_size=2)
    p._open = opener  # type: ignore[method-assign]
    conn = await p._checkout()
    await p.close()
    await p.release(conn)
    assert conn.closed


@pytest.mark.asyncio
async def test_async_close_is_idempotent() -> None:
    conns: list[_AsyncConn] = []

    async def opener() -> _AsyncConn:
        c = _AsyncConn()
        conns.append(c)
        return c

    p = pool_mod.AsyncConnectionPool({"ashost": "h"}, min_size=0, max_size=2)
    p._open = opener  # type: ignore[method-assign]
    async with p.acquire(timeout=1.0):
        pass
    await p.close()
    assert conns[0].closed
    await p.close()
    assert all(c.closed for c in conns)
