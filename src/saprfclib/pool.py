# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — connection pool
#
# A thread-safe, bounded pool of ready Connection objects (POOL-01..04). It wraps
# the existing Connection unchanged — pure orchestration over connect()/ping()/
# close(), no protocol knowledge.
#
#     ConnectionPool(params, min_size=1, max_size=10)
#                                     -- warm min_size connections at init (POOL-01)
#     acquire(timeout=30.0)           -- @contextmanager: lend single-owner, ping-
#                                        before-lend, auto-release on exit (POOL-02/03)
#     release(conn)                   -- return a connection to the idle set (POOL-04)
#     close()                         -- close every pooled connection (graceful)
#
# Concurrency model (D-13): a single ``threading.Condition`` guards ALL pool state
# (idle deque, in-use set, created counter). ``acquire`` waits on the condition
# with a ``time.monotonic`` deadline (never ``time.time`` — wall-clock can jump);
# ``release`` returns the connection and ``notify()``s one waiter.
#
# Ping happens OUTSIDE the lock (RESEARCH Pitfall 2): a candidate is popped under
# the lock and provisionally counted out, the lock is released, ``ping()`` runs
# (it does network I/O and may block for the socket timeout), then the lock is
# re-acquired to either lend the healthy connection or discard+replace a dead one
# (POOL-03). Holding the lock across a ping would stall every other acquirer.
#
# Security: the pool holds credentials in ``params`` (passed straight to connect).
# Those are NEVER logged and NEVER placed in a PoolTimeoutError message — the
# timeout carries only counts/state (threat T-05-P03 / T-04-CRED). The ``max_size``
# hard cap prevents unbounded connection growth (T-05-P01): the pool raises
# PoolTimeoutError instead of growing past the ceiling.
from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any

import saprfclib.connection as _connection
from saprfclib.exceptions import PoolTimeoutError

_logger = logging.getLogger(__name__)

__all__ = ["ConnectionPool", "AsyncConnectionPool"]


class ConnectionPool:
    """A bounded, thread-safe pool of ready Connection objects (POOL-01..04).

    ``params`` is the same keyword dict :func:`saprfclib.connect` accepts (D-10).
    ``min_size`` connections are opened eagerly at construction (warm-up); the
    pool then grows lazily up to ``max_size`` under demand. Acquire/release are
    safe from any number of threads concurrently.
    """

    def __init__(
        self,
        params: dict[str, Any],
        min_size: int = 1,
        max_size: int = 10,
    ) -> None:
        if min_size < 0:
            raise ValueError("min_size must be >= 0")
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        if min_size > max_size:
            raise ValueError("min_size must be <= max_size")

        self._params: dict[str, Any] = dict(params)
        self._max_size = max_size
        self._cv = threading.Condition()
        self._idle: deque[Any] = deque()
        self._in_use: set[Any] = set()
        self._created = 0
        self._closed = False

        # Warm-up (POOL-01): pre-open min_size connections before any acquire.
        for _ in range(min_size):
            conn = self._open()
            self._idle.append(conn)
            self._created += 1

    # ------------------------------------------------------------------ #
    # Connection lifecycle seams (all real network/Connection touch points)
    # ------------------------------------------------------------------ #
    def _open(self) -> Any:
        """Open a fresh Connection via the saprfclib.connect() factory (D-10).

        Dispatches through the ``saprfclib.connection`` module attribute (not a
        bound name) so the factory seam stays patchable for offline tests.
        """
        return _connection.connect(**self._params)

    def _ping_ok(self, conn: Any) -> bool:
        """True iff ``conn.ping()`` reports liveness. Any False/exception is dead.

        Called OUTSIDE the Condition lock (Pitfall 2). Treats both a falsy ping
        result and any raised exception as a dead connection.
        """
        try:
            return bool(conn.ping())
        except Exception as exc:  # noqa: BLE001 — any failure means "do not lend it"
            # Discarding the connection is right; doing it without a word is not.
            # A pool that quietly bins every connection it checks looks to the caller
            # like a slow pool rather than a broken one.
            _logger.debug(
                "pool: discarding a connection that failed its health check (%s: %s)",
                type(exc).__name__,
                exc,
            )
            return False

    def _safe_close(self, conn: Any) -> None:
        """Close a connection, swallowing any error (close is best-effort)."""
        try:
            conn.close()
        except Exception as exc:  # noqa: BLE001 — close is best-effort
            _logger.debug("pool: error while closing a discarded connection: %s", exc)

    # ------------------------------------------------------------------ #
    # Public acquire/release surface
    # ------------------------------------------------------------------ #
    @contextmanager
    def acquire(self, timeout: float = 30.0) -> Iterator[Any]:
        """Lend a single-owner Connection for the duration of the ``with`` block.

        Blocks up to ``timeout`` seconds for a connection to become available,
        ping-checking it before lending (D-12); auto-releases on block exit,
        including on exception (D-11, POOL-02). Raises :class:`PoolTimeoutError`
        if the deadline elapses while the pool is exhausted.
        """
        conn = self._checkout(timeout)
        try:
            yield conn
        finally:
            self.release(conn)

    def _checkout(self, timeout: float) -> Any:
        """Check out a healthy connection or raise PoolTimeoutError on deadline.

        Predicate loop under the Condition (D-13):
          1. Reuse an idle connection, ping-checked OUTSIDE the lock (Pitfall 2):
             pop under lock + provisionally count out, release lock, ping, then
             re-acquire to lend (healthy) or discard+replace (dead, POOL-03).
          2. Otherwise lazily grow toward max_size (POOL-01).
          3. Otherwise wait on the condition until a release or the deadline.
        """
        deadline = time.monotonic() + timeout
        discarded = 0
        with self._cv:
            while True:
                if self._closed:
                    raise RuntimeError("pool is closed")

                # 1) Try to reuse an idle connection, ping-checked outside the lock.
                if self._idle:
                    candidate = self._idle.popleft()
                    # Provisionally mark it out so no other thread can grab it and
                    # so _created accounting stays consistent across the lock gap.
                    self._in_use.add(candidate)
                    self._cv.release()
                    try:
                        healthy = self._ping_ok(candidate)
                    finally:
                        self._cv.acquire()
                    if healthy:
                        return candidate
                    # Dead connection: discard + replace (POOL-03).
                    self._in_use.discard(candidate)
                    self._created -= 1
                    discarded += 1
                    self._cv.release()
                    try:
                        self._safe_close(candidate)
                    finally:
                        self._cv.acquire()
                    # A slot freed up; let a waiter know and re-loop.
                    self._cv.notify()
                    continue

                # 2) Lazily grow toward max_size.
                if self._created < self._max_size:
                    self._created += 1
                    self._cv.release()
                    try:
                        fresh = self._open()
                    except Exception:
                        # Open failed: undo the reservation and surface the error.
                        self._cv.acquire()
                        self._created -= 1
                        self._cv.notify()
                        raise
                    else:
                        self._cv.acquire()
                    self._in_use.add(fresh)
                    return fresh

                # 3) Exhausted: wait for a release or the deadline.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PoolTimeoutError(
                        waited=timeout,
                        discarded=discarded,
                        active=len(self._in_use),
                        idle=len(self._idle),
                        max_size=self._max_size,
                    )
                self._cv.wait(remaining)

    def release(self, conn: Any) -> None:
        """Return a lent connection to the idle set and wake one waiter (POOL-04)."""
        with self._cv:
            self._in_use.discard(conn)
            if self._closed:
                # Pool shut down while this connection was out: close it instead of
                # returning it to a defunct idle set.
                self._created -= 1
                self._cv.release()
                try:
                    self._safe_close(conn)
                finally:
                    self._cv.acquire()
                self._cv.notify()
                return
            self._idle.append(conn)
            self._cv.notify()

    def close(self) -> None:
        """Close every pooled connection (idle + in-use) and mark the pool closed.

        Idle connections are closed immediately. In-use connections are closed on
        their next ``release()``. Idempotent.
        """
        with self._cv:
            if self._closed:
                return
            self._closed = True
            idle_conns = list(self._idle)
            self._idle.clear()
            self._created -= len(idle_conns)
            self._cv.notify_all()
        # Close outside the lock (close may do I/O).
        for conn in idle_conns:
            self._safe_close(conn)


# --------------------------------------------------------------------------- #
# AsyncConnectionPool — asyncio-native single-owner pool (D-08 / POOL-01..04)
# --------------------------------------------------------------------------- #


class AsyncConnectionPool:
    """Bounded, asyncio-native pool of ready AsyncConnection objects (D-08 / POOL-01..04).

    ``params`` is the same keyword dict :func:`saprfclib.connect_async` accepts.
    Connections are never opened eagerly in ``__init__`` (cannot ``await`` there);
    call ``await pool.start()`` to pre-open ``min_size`` connections, or rely on
    lazy growth on first acquire.  Acquire/release are safe from any number of
    concurrent asyncio tasks.

    Ping happens OUTSIDE the async lock (Pitfall 2, mirroring ConnectionPool):
    a candidate is popped under the Condition then the lock is released before
    ``await conn.ping()``, re-acquired afterwards.  Holding the lock across a
    ping would stall every other task waiting for a connection.

    Security (T-09-05-P03): the pool holds credentials in ``params``.  Those are
    NEVER logged and NEVER placed in a :class:`PoolTimeoutError` message — the
    timeout carries only counts/state, never connection params.

    Usage::

        pool = AsyncConnectionPool(params, min_size=0, max_size=5)
        await pool.start()   # optional eager warm-up
        async with pool.acquire(timeout=30.0) as conn:
            result = await conn.call("STFC_CONNECTION", REQUTEXT="Hi")
        await pool.close()
    """

    def __init__(
        self,
        params: dict[str, Any],
        min_size: int = 1,
        max_size: int = 10,
    ) -> None:
        if min_size < 0:
            raise ValueError("min_size must be >= 0")
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        if min_size > max_size:
            raise ValueError("min_size must be <= max_size")

        self._params: dict[str, Any] = dict(params)
        self._max_size = max_size
        self._min_size = min_size
        # Single asyncio.Condition guards ALL pool state (idle deque, in_use set,
        # _created counter).  Its underlying asyncio.Lock is the boundary for
        # pool mutations; the Condition is used for wait/notify on exhaustion.
        self._cond: asyncio.Condition = asyncio.Condition()
        self._idle: deque[Any] = deque()
        self._in_use: set[Any] = set()
        self._created = 0
        # Cumulative, not per-checkout: _checkout runs inside a wait_for, so a
        # timeout unwinds it and any counter local to it is lost with the frame.
        # acquire() snapshots this before and after to get the per-wait figure.
        self._discarded_total = 0
        self._closed = False

    # ------------------------------------------------------------------ #
    # Eager warm-up (cannot await in __init__)
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Open ``min_size`` connections eagerly (POOL-01 warm-up).

        Cannot run in ``__init__`` because ``await`` is not allowed there.
        Call this after constructing the pool if eager warm-up is needed;
        otherwise the pool opens connections lazily on the first ``acquire()``.
        """
        for _ in range(self._min_size):
            conn = await self._open()
            async with self._cond:
                self._idle.append(conn)
                self._created += 1
                self._cond.notify()

    # ------------------------------------------------------------------ #
    # Connection lifecycle seams (all real async I/O touch points)
    # ------------------------------------------------------------------ #

    async def _open(self) -> Any:
        """Open a fresh AsyncConnection via the connect_async() factory seam (D-10).

        Dispatches through the ``saprfclib.connection`` module attribute (not a
        bound name) so the factory seam stays patchable for offline tests —
        mirrors ConnectionPool._open().
        """
        return await _connection.connect_async(**self._params)

    async def _ping_ok(self, conn: Any) -> bool:
        """True iff ``await conn.ping()`` reports liveness.  Called OUTSIDE the lock.

        Any ``Exception`` (including CommunicationError) means the connection is
        dead.  ``asyncio.CancelledError`` is ``BaseException`` and propagates
        without being caught (Pitfall 7 — never swallow cancellation).
        """
        try:
            return bool(await conn.ping())
        except Exception as exc:  # noqa: BLE001 — any failure means "do not lend it"
            _logger.debug(
                "pool: discarding a connection that failed its health check (%s: %s)",
                type(exc).__name__,
                exc,
            )
            return False

    async def _safe_close(self, conn: Any) -> None:
        """Close a connection, swallowing any ``Exception`` (close is best-effort).

        ``asyncio.CancelledError`` (``BaseException``) propagates — not caught by
        ``except Exception`` (Pitfall 7).
        """
        try:
            await conn.close()
        except Exception as exc:  # noqa: BLE001 — close is best-effort
            _logger.debug("pool: error while closing a discarded connection: %s", exc)

    # ------------------------------------------------------------------ #
    # Public acquire / release surface
    # ------------------------------------------------------------------ #

    @asynccontextmanager
    async def acquire(self, timeout: float = 30.0) -> AsyncIterator[Any]:
        """Lend a single-owner AsyncConnection for the duration of the ``async with`` block.

        Blocks up to ``timeout`` seconds for a connection to become available,
        ping-checking it before lending; auto-releases on block exit, including on
        exception (D-11, POOL-02).  Raises :class:`PoolTimeoutError` if the deadline
        elapses while the pool is exhausted (counts only, no credentials — T-09-05-P03).
        """
        discarded_before = self._discarded_total
        try:
            conn = await asyncio.wait_for(self._checkout(), timeout=timeout)
        except TimeoutError as exc:
            async with self._cond:
                # Was 0 unconditionally, which turned the one field that distinguishes
                # "the pool is busy" from "the pool is churning dead connections" into
                # a constant. A caller reading it was told the pool was simply full.
                raise PoolTimeoutError(
                    waited=timeout,
                    discarded=self._discarded_total - discarded_before,
                    active=len(self._in_use),
                    idle=len(self._idle),
                    max_size=self._max_size,
                ) from exc
        try:
            yield conn
        finally:
            await self.release(conn)

    async def _checkout(self) -> Any:
        """Check out a healthy connection or raise on close; ping OUTSIDE the lock (Pitfall 2).

        Loop structure mirrors ConnectionPool._checkout with asyncio.Condition:

        1. Pop idle under the Condition, release lock, ``await ping``, re-acquire:
           healthy → return; dead → discard + replace (POOL-03).
        2. Lazily grow toward ``max_size``: increment counter under lock, release
           lock, ``await _open()``, re-acquire.
        3. Exhausted: ``await cond.wait()`` — releases lock, suspends the task,
           re-acquires on ``notify()`` from ``release()``.
        """
        while True:
            candidate = None

            async with self._cond:
                if self._closed:
                    raise RuntimeError("pool is closed")

                # 1) Reuse an idle connection — ping-checked OUTSIDE the lock.
                if self._idle:
                    candidate = self._idle.popleft()
                    self._in_use.add(candidate)
                elif self._created < self._max_size:
                    # 2) Reserve a slot and open outside the lock.
                    self._created += 1
                else:
                    # 3) Exhausted — suspend until release() calls notify().
                    await self._cond.wait()
                    continue

            # ---- Outside the Condition lock — do async I/O here ---- #
            if candidate is not None:
                # Ping OUTSIDE the lock (Pitfall 2).
                healthy = await self._ping_ok(candidate)
                if healthy:
                    return candidate
                # Dead connection: discard + replace (POOL-03).
                async with self._cond:
                    self._in_use.discard(candidate)
                    self._created -= 1
                    self._discarded_total += 1
                    self._cond.notify()
                await self._safe_close(candidate)
                # Loop to try again (either idle remains or we open a new one).
            else:
                # need_new is True: open a fresh connection outside the lock.
                try:
                    fresh = await self._open()
                except Exception:
                    # Open failed: undo the reservation and surface the error.
                    async with self._cond:
                        self._created -= 1
                        self._cond.notify()
                    raise
                async with self._cond:
                    self._in_use.add(fresh)
                return fresh

    async def release(self, conn: Any) -> None:
        """Return a lent connection to the idle set and wake one waiter (POOL-04).

        If the pool was closed while the connection was out, close it instead of
        returning it to a defunct idle set.
        """
        close_it = False
        async with self._cond:
            self._in_use.discard(conn)
            if self._closed:
                # Pool shut down while this connection was lent: close on release.
                self._created -= 1
                self._cond.notify()
                close_it = True
            else:
                self._idle.append(conn)
                self._cond.notify()
        if close_it:
            await self._safe_close(conn)

    async def close(self) -> None:
        """Close every pooled connection (idle + in-use) and mark the pool closed.

        Idle connections are closed immediately.  In-use connections are closed on
        their next ``release()``.  Idempotent.
        """
        async with self._cond:
            if self._closed:
                return
            self._closed = True
            idle_conns = list(self._idle)
            self._idle.clear()
            self._created -= len(idle_conns)
            self._cond.notify_all()
        # Close outside the lock (close may do async I/O).
        for conn in idle_conns:
            await self._safe_close(conn)
