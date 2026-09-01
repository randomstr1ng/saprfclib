# SPDX-License-Identifier: MPL-2.0
"""Pool-level metrics (#22, the half that was still open).

Connection metrics answer "how long did the call take". These answer the
question that comes before it: was the caller even holding a connection yet? A
high mean wait with no timeouts says the pool is undersized; timeouts say badly
undersized; a high discard rate says connections are dying between uses and that
cost is being paid on every acquire. None of that is visible from CallStats,
because none of it happens during a call.

The accounting is where this gets subtle, so most of what follows is about
counting the awkward cases correctly rather than the happy path.
"""

from __future__ import annotations

import asyncio
import threading
from collections import deque
from typing import Any

import pytest

from saprfclib.exceptions import PoolTimeoutError
from saprfclib.pool import ConnectionPool, PoolMetrics


class _Conn:
    def __init__(self, healthy: bool = True) -> None:
        self.healthy = healthy
        self.closed = False

    def ping(self) -> bool:
        return self.healthy

    def close(self) -> None:
        self.closed = True


def _pool(max_size: int = 2, opener: Any = None) -> ConnectionPool:
    """A pool with __init__ bypassed, so no sockets are opened."""
    p = ConnectionPool.__new__(ConnectionPool)
    p._cv = threading.Condition()
    p._idle = deque()
    p._in_use = set()
    p._created = 0
    p._max_size = max_size
    p._closed = False
    p._params = {}
    p.metrics = PoolMetrics()
    p._open = opener or (lambda: _Conn())  # type: ignore[method-assign]
    return p


def test_a_fresh_pool_reports_zeroes_without_dividing_by_them() -> None:
    m = PoolMetrics()
    assert m.mean_wait_s == 0.0
    assert m.hit_rate == 0.0
    assert m.as_dict()["acquires"] == 0


def test_reuse_counts_as_a_hit_and_a_new_connection_does_not() -> None:
    pool = _pool()
    first = pool._checkout(timeout=1.0)
    assert pool.metrics.creates == 1
    assert pool.metrics.hits == 0
    assert pool.metrics.acquires == 1

    pool.release(first)
    second = pool._checkout(timeout=1.0)
    assert second is first
    assert pool.metrics.hits == 1
    assert pool.metrics.creates == 1, "reuse must not look like an open"
    assert pool.metrics.hit_rate == 0.5  # one of two acquires was served from idle


def test_a_connection_that_fails_its_health_check_is_a_discard_not_a_hit() -> None:
    """Crediting it as a hit would report a reuse nobody could use.

    The acquire that follows is satisfied by a freshly opened connection, so the
    numbers have to show one discard and one create -- not one hit.
    """
    pool = _pool()
    dead = _Conn(healthy=False)
    pool._idle.append(dead)
    pool._created = 1

    conn = pool._checkout(timeout=1.0)
    assert conn is not dead
    assert dead.closed is True
    assert pool.metrics.discards == 1
    assert pool.metrics.hits == 0
    assert pool.metrics.creates == 1
    assert pool.metrics.acquires == 1


def test_a_failed_open_is_not_counted_as_a_create() -> None:
    """The reservation is undone, so the connection never existed.

    Leaving it counted would show a pool steadily opening connections that are
    not there, which reads as a leak rather than as a failing server.
    """

    def boom() -> Any:
        raise OSError("connect refused")

    pool = _pool(opener=boom)
    with pytest.raises(OSError):
        pool._checkout(timeout=1.0)
    assert pool.metrics.creates == 0
    assert pool.metrics.acquires == 0
    assert pool.size == 0, "the slot reservation must be released too"


def test_a_timeout_is_counted_and_its_wait_is_included_in_the_mean() -> None:
    """Dropping the longest waits would make an exhausted pool look fast.

    A caller that waited the full deadline and got nothing waited longer than
    anyone who succeeded, so the mean divides by acquires plus timeouts.
    """
    pool = _pool(max_size=1)
    held = pool._checkout(timeout=1.0)
    assert held is not None

    with pytest.raises(PoolTimeoutError):
        pool._checkout(timeout=0.05)

    assert pool.metrics.timeouts == 1
    assert pool.metrics.acquires == 1
    assert pool.metrics.max_wait_s >= 0.05
    # mean over both attempts, not just the one that succeeded
    assert pool.metrics.mean_wait_s == pytest.approx(pool.metrics.total_wait_s / 2, rel=1e-9)


def test_stats_carries_the_live_gauges_alongside_the_counters() -> None:
    pool = _pool(max_size=3)
    a = pool._checkout(timeout=1.0)
    b = pool._checkout(timeout=1.0)
    pool.release(b)

    stats = pool.stats()
    assert stats["in_use"] == 1
    assert stats["idle"] == 1
    assert stats["size"] == 2
    assert stats["max_size"] == 3
    assert stats["acquires"] == 2
    assert all(isinstance(v, (int, float)) for v in stats.values()), "flat, exporter-ready"
    del a


def test_hit_rate_zero_is_distinguishable_from_no_traffic() -> None:
    """Which is why acquires is exported next to it.

    An unqualified 0.0 reads as "the pool never reuses anything" when it may
    only mean nothing has happened yet.
    """
    idle_pool = _pool()
    assert idle_pool.metrics.hit_rate == 0.0
    assert idle_pool.metrics.acquires == 0

    busy = _pool()
    busy._checkout(timeout=1.0)
    assert busy.metrics.hit_rate == 0.0
    assert busy.metrics.acquires == 1


@pytest.mark.asyncio
async def test_the_async_pool_keeps_the_same_books() -> None:
    from saprfclib.pool import AsyncConnectionPool

    class _AConn:
        def __init__(self, healthy: bool = True) -> None:
            self.healthy = healthy

        async def ping(self) -> bool:
            return self.healthy

        async def close(self) -> None:
            return None

    pool = AsyncConnectionPool.__new__(AsyncConnectionPool)
    pool._cond = asyncio.Condition()
    pool._idle = deque()
    pool._in_use = set()
    pool._created = 0
    pool._max_size = 2
    pool._closed = False
    pool._discarded_total = 0
    pool.metrics = PoolMetrics()
    pool._open = lambda: _fresh()  # type: ignore[method-assign]

    async def _fresh() -> Any:
        return _AConn()

    async with pool.acquire(timeout=1.0) as first:
        assert first is not None
    assert pool.metrics.creates == 1
    assert pool.metrics.acquires == 1

    async with pool.acquire(timeout=1.0) as second:
        assert second is not None
    assert pool.metrics.hits == 1, "the released connection must be reused"
    assert pool.metrics.creates == 1
