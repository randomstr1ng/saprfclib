# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Pool waiters are served in arrival order, and ``max_waiters`` sheds overload (#84).

The pool used to wake waiters with ``Condition.notify()``. That wakes *a* waiter but
does not hand it the connection: a thread arriving between the release and the
wake-up could take it first, and under steady load a caller could be overtaken until
its deadline. These tests pin the behaviour that replaced it, for both pools.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from saprfclib import PoolOverloadedError, PoolTimeoutError
from saprfclib.pool import AsyncConnectionPool, ConnectionPool


class _Conn:
    def __init__(self, n: int, healthy: bool = True) -> None:
        self.n = n
        self.healthy = healthy
        self.closed = False

    def ping(self) -> bool:
        return self.healthy

    def close(self) -> None:
        self.closed = True


class _Pool(ConnectionPool):
    """A pool that opens fake connections instead of sockets."""

    def __init__(self, max_size: int = 1, **kwargs: Any) -> None:
        self._opened = 0
        super().__init__({}, min_size=0, max_size=max_size, **kwargs)

    def _open(self) -> Any:
        self._opened += 1
        return _Conn(self._opened)


def _wait_until(predicate: Any, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        time.sleep(0.001)


# --------------------------------------------------------------------------- #
# ConnectionPool
# --------------------------------------------------------------------------- #


def test_a_caller_arriving_after_a_release_does_not_take_the_connection_from_a_waiter() -> None:
    pool = _Pool(max_size=1)
    held = pool._checkout(1.0)
    got: list[Any] = []
    waiter = threading.Thread(target=lambda: got.append(pool._checkout(5.0)))
    waiter.start()
    _wait_until(lambda: pool.waiting == 1)

    pool.release(held)
    # The waiter is still asleep or just waking. A newcomer must queue behind it, so
    # with no time to wait it gets nothing -- before #84 it took the connection.
    with pytest.raises(PoolTimeoutError):
        pool._checkout(0.0)

    waiter.join(5.0)
    assert got == [held]
    pool.release(held)
    assert pool.waiting == 0


def test_waiters_are_served_in_the_order_they_arrived() -> None:
    pool = _Pool(max_size=1)
    held = pool._checkout(1.0)
    order: list[int] = []

    def worker(i: int) -> None:
        conn = pool._checkout(10.0)
        order.append(i)
        pool.release(conn)

    threads = []
    for i in range(8):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)
        _wait_until(lambda i=i: pool.waiting == i + 1)

    pool.release(held)
    for t in threads:
        t.join(10.0)
    assert order == list(range(8))
    assert (pool.in_use, pool.waiting, pool.size) == (0, 0, 1)


def test_a_waiter_that_times_out_passes_its_turn_on() -> None:
    pool = _Pool(max_size=1)
    held = pool._checkout(1.0)
    errors: list[BaseException] = []
    got: list[Any] = []

    def impatient() -> None:
        try:
            pool._checkout(0.05)
        except PoolTimeoutError as exc:
            errors.append(exc)

    first = threading.Thread(target=impatient)
    first.start()
    _wait_until(lambda: pool.waiting == 1)
    second = threading.Thread(target=lambda: got.append(pool._checkout(5.0)))
    second.start()
    _wait_until(lambda: pool.waiting == 2)

    first.join(5.0)
    assert len(errors) == 1
    pool.release(held)
    second.join(5.0)
    assert got == [held]


def test_max_waiters_refuses_the_overflow_without_waiting_or_leaking() -> None:
    pool = _Pool(max_size=1, max_waiters=1)
    held = pool._checkout(1.0)
    got: list[Any] = []
    waiter = threading.Thread(target=lambda: got.append(pool._checkout(5.0)))
    waiter.start()
    _wait_until(lambda: pool.waiting == 1)

    started = time.monotonic()
    with pytest.raises(PoolOverloadedError) as info:
        pool._checkout(30.0)
    assert time.monotonic() - started < 1.0
    assert (info.value.waiters, info.value.max_waiters) == (1, 1)
    assert (info.value.active, info.value.idle, info.value.max_size) == (1, 0, 1)
    assert pool.metrics.overloads == 1
    assert pool.metrics.timeouts == 0
    assert pool.stats()["overloads"] == 1
    assert pool.waiting == 1

    pool.release(held)
    waiter.join(5.0)
    assert got == [held]
    pool.release(held)
    assert (pool.in_use, pool.idle, pool.size, pool.waiting) == (0, 1, 1, 0)


def test_max_waiters_zero_never_waits_but_still_lends_a_free_connection() -> None:
    pool = _Pool(max_size=1, max_waiters=0)
    with pool.acquire() as conn:
        with pytest.raises(PoolOverloadedError):
            pool._checkout(30.0)
    with pool.acquire() as again:
        assert again is conn


def test_a_waiter_whose_connection_fails_its_health_check_keeps_its_place() -> None:
    pool = _Pool(max_size=1)
    held = pool._checkout(1.0)
    order: list[str] = []

    def worker(name: str) -> None:
        conn = pool._checkout(10.0)
        order.append(name)
        pool.release(conn)

    first = threading.Thread(target=worker, args=("first",))
    first.start()
    _wait_until(lambda: pool.waiting == 1)
    second = threading.Thread(target=worker, args=("second",))
    second.start()
    _wait_until(lambda: pool.waiting == 2)

    held.healthy = False  # the first waiter gets a dead connection, then a new one
    pool.release(held)
    first.join(10.0)
    second.join(10.0)
    assert order == ["first", "second"]
    assert held.closed


def test_close_wakes_every_waiter() -> None:
    pool = _Pool(max_size=1)
    pool._checkout(1.0)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            pool._checkout(30.0)
        except RuntimeError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    _wait_until(lambda: pool.waiting == 3)
    pool.close()
    for t in threads:
        t.join(5.0)
    assert len(errors) == 3
    assert pool.waiting == 0


def test_max_waiters_must_not_be_negative() -> None:
    with pytest.raises(ValueError, match="max_waiters"):
        _Pool(max_waiters=-1)
    with pytest.raises(ValueError, match="max_waiters"):
        AsyncConnectionPool({}, min_size=0, max_waiters=-1)


@settings(max_examples=25, deadline=None)
@given(
    max_size=st.integers(min_value=1, max_value=3),
    callers=st.integers(min_value=1, max_value=10),
)
def test_under_contention_every_caller_is_served_and_nothing_leaks(
    max_size: int, callers: int
) -> None:
    pool = _Pool(max_size=max_size)
    served: list[int] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        for _ in range(3):
            with pool.acquire(timeout=10.0):
                with lock:
                    served.append(i)
                time.sleep(0.0005)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(callers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30.0)
    assert sorted(served) == sorted(list(range(callers)) * 3)
    assert pool.metrics.timeouts == 0
    assert (pool.in_use, pool.waiting) == (0, 0)
    assert pool.size <= max_size


# --------------------------------------------------------------------------- #
# AsyncConnectionPool
# --------------------------------------------------------------------------- #


class _AConn:
    def __init__(self, n: int) -> None:
        self.n = n
        self.closed = False

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        self.closed = True


class _APool(AsyncConnectionPool):
    def __init__(self, max_size: int = 1, **kwargs: Any) -> None:
        super().__init__({}, min_size=0, max_size=max_size, **kwargs)
        self._opened = 0
        self.open_gate: asyncio.Event | None = None

    async def _open(self) -> Any:
        if self.open_gate is not None:
            await self.open_gate.wait()
        self._opened += 1
        return _AConn(self._opened)


async def _settle(predicate: Any) -> None:
    for _ in range(1000):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


@settings(max_examples=25, deadline=None)
@given(
    max_size=st.integers(min_value=1, max_value=3),
    callers=st.integers(min_value=1, max_value=10),
)
def test_async_waiters_are_served_in_arrival_order(max_size: int, callers: int) -> None:
    async def main() -> list[int]:
        pool = _APool(max_size=max_size)
        held = [await pool._checkout() for _ in range(max_size)]
        order: list[int] = []

        async def worker(i: int) -> None:
            async with pool.acquire(timeout=10.0):
                order.append(i)
                await asyncio.sleep(0)

        tasks = []
        for i in range(callers):
            tasks.append(asyncio.create_task(worker(i)))
            await _settle(lambda i=i: pool.waiting == i + 1)
        for conn in held:
            await pool.release(conn)
        await asyncio.gather(*tasks)
        assert (pool.in_use, pool.waiting) == (0, 0)
        return order

    assert asyncio.run(main()) == list(range(callers))


def test_async_newcomer_does_not_take_a_released_connection_from_a_waiter() -> None:
    async def main() -> None:
        pool = _APool(max_size=1)
        held = await pool._checkout()
        waiter = asyncio.create_task(pool._checkout())
        await _settle(lambda: pool.waiting == 1)
        await pool.release(held)
        # Released but not yet picked up: the waiter has not run since its wake-up.
        with pytest.raises(PoolTimeoutError):
            async with pool.acquire(timeout=0.01):
                pass
        assert await waiter is held

    asyncio.run(main())


def test_async_max_waiters_refuses_the_overflow() -> None:
    async def main() -> None:
        pool = _APool(max_size=1, max_waiters=1)
        held = await pool._checkout()
        waiter = asyncio.create_task(pool._checkout())
        await _settle(lambda: pool.waiting == 1)
        with pytest.raises(PoolOverloadedError):
            async with pool.acquire(timeout=30.0):
                pass
        assert pool.metrics.overloads == 1
        await pool.release(held)
        assert await waiter is held
        await pool.release(held)
        assert (pool.in_use, pool.idle, pool.size, pool.waiting) == (0, 1, 1, 0)

    asyncio.run(main())


def test_async_timeout_during_open_releases_the_reserved_slot() -> None:
    async def main() -> None:
        pool = _APool(max_size=1)
        pool.open_gate = asyncio.Event()  # the open never completes
        with pytest.raises(PoolTimeoutError):
            async with pool.acquire(timeout=0.01):
                pass
        # Before #84 the cancelled open stayed counted, and the pool was full forever.
        assert (pool.size, pool.metrics.creates) == (0, 0)
        pool.open_gate.set()
        async with pool.acquire(timeout=1.0) as conn:
            assert conn.n == 1

    asyncio.run(main())


def test_async_close_wakes_every_waiter() -> None:
    async def main() -> None:
        pool = _APool(max_size=1)
        await pool._checkout()
        tasks = [asyncio.create_task(pool._checkout()) for _ in range(3)]
        await _settle(lambda: pool.waiting == 3)
        await pool.close()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert all(isinstance(r, RuntimeError) for r in results)
        assert pool.waiting == 0

    asyncio.run(main())
