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
# with a ``time.monotonic`` deadline (never ``time.time`` — wall-clock can jump).
#
# Fairness (#84): callers that cannot be served at once queue in arrival order, each
# on its own Event, and only the head of the queue may take a released connection.
# A ``notify()`` on one shared Condition promised none of that: a thread arriving just
# as a connection came back could take it ahead of one that had waited for seconds,
# and under steady load a waiter could starve until its deadline. A caller arriving
# while others queue joins the back; it never takes a connection ahead of them. An
# optional ``max_waiters`` bounds that queue: past it, ``acquire`` raises
# PoolOverloadedError instead of waiting.
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
import uuid
from collections import deque
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any

import saprfclib.connection as _connection
from saprfclib.exceptions import PoolOverloadedError, PoolTimeoutError
from saprfclib.metadata import MetadataCache
from saprfclib.session import SessionState

_logger = logging.getLogger(__name__)

__all__ = ["ConnectionPool", "AsyncConnectionPool"]


def _is_retired(conn: Any) -> bool:
    """True if the connection has already retired itself as unusable.

    A connection whose reply could not be read to its end marks its session
    BROKEN, and every operation on it then refuses. The health check would find
    that out anyway -- ping() raises and _ping_ok treats any exception as dead --
    but only after building and sending a frame onto a stream already known to be
    unreadable. Asking first makes the discard deliberate rather than incidental,
    and keeps a real protocol fault out of the "failed its health check" log line,
    where it would read as a network blip.
    """
    session = getattr(conn, "_session", None)
    return bool(session is not None and session.state is SessionState.BROKEN)


class PoolMetrics:
    """Running totals for one pool, shaped for a metrics exporter.

    Answers the question a connection-level metric cannot: when a call was slow,
    was it slow *before it even had a connection*? A high mean wait with few
    timeouts says the pool is undersized; timeouts say it is badly undersized;
    a high discard rate says connections are dying between uses and the cost is
    being paid on every acquire.

    ``hits`` and ``creates`` are counted so the two ways of satisfying an acquire
    stay distinguishable. A connection taken from idle that then fails its health
    check is neither: it is a ``discard`` followed by whatever satisfies the retry,
    because counting it as a hit would credit the pool for a connection nobody
    could use.

    Every counter is updated while the pool's Condition is held, so the totals are
    consistent with the state they describe. Instrumentation is unconditional: the
    counters are integer increments under a lock the pool was already holding, and
    one ``monotonic()`` per acquire against the cost of opening or health-checking
    a socket. A flag to switch that off would add a branch and a configuration
    surface to save nothing measurable.
    """

    __slots__ = (
        "acquires",
        "timeouts",
        "hits",
        "creates",
        "discards",
        "overloads",
        "total_wait_s",
        "max_wait_s",
    )

    def __init__(self) -> None:
        self.acquires = 0
        self.timeouts = 0
        self.hits = 0
        self.creates = 0
        self.discards = 0
        # Callers refused by max_waiters (#84). Not counted in acquires or timeouts:
        # they never waited, so folding them into the wait statistics would make an
        # overloaded pool look fast.
        self.overloads = 0
        self.total_wait_s = 0.0
        self.max_wait_s = 0.0

    def _record_wait(self, waited: float) -> None:
        self.total_wait_s += waited
        self.max_wait_s = max(self.max_wait_s, waited)

    @property
    def mean_wait_s(self) -> float:
        """Mean time an acquire spent waiting, over acquires that finished.

        Divides by acquires plus timeouts: a caller that waited the full deadline
        and got nothing waited longest of all, and dropping it would make an
        exhausted pool look faster than a healthy one.
        """
        attempts = self.acquires + self.timeouts
        return self.total_wait_s / attempts if attempts else 0.0

    @property
    def hit_rate(self) -> float:
        """Share of acquires served from an idle connection rather than a new one.

        0.0 when nothing has been acquired yet, which is why ``acquires`` is
        exported alongside it -- an unqualified 0.0 would read as "the pool never
        reuses anything" rather than "nothing has happened".
        """
        return self.hits / self.acquires if self.acquires else 0.0

    def as_dict(self) -> dict[str, float | int]:
        """A flat mapping, shaped for a metrics exporter."""
        return {
            "acquires": self.acquires,
            "timeouts": self.timeouts,
            "hits": self.hits,
            "creates": self.creates,
            "discards": self.discards,
            "overloads": self.overloads,
            "total_wait_s": self.total_wait_s,
            "mean_wait_s": self.mean_wait_s,
            "max_wait_s": self.max_wait_s,
            "hit_rate": self.hit_rate,
        }

    def __repr__(self) -> str:
        return (
            f"PoolMetrics(acquires={self.acquires}, timeouts={self.timeouts}, "
            f"hit_rate={self.hit_rate:.2f}, "
            f"mean_wait={self.mean_wait_s * 1000:.1f}ms, discards={self.discards}, "
            f"overloads={self.overloads})"
        )


def _check_sizes(min_size: int, max_size: int, max_waiters: int | None) -> None:
    if min_size < 0:
        raise ValueError("min_size must be >= 0")
    if max_size < 1:
        raise ValueError("max_size must be >= 1")
    if min_size > max_size:
        raise ValueError("min_size must be <= max_size")
    if max_waiters is not None and max_waiters < 0:
        raise ValueError("max_waiters must be >= 0 or None")


class ConnectionPool:
    """A bounded, thread-safe pool of ready Connection objects (POOL-01..04).

    ``params`` is the same keyword dict :func:`saprfclib.connect` accepts (D-10).
    ``min_size`` connections are opened eagerly at construction (warm-up); the
    pool then grows lazily up to ``max_size`` under demand. Acquire/release are
    safe from any number of threads concurrently.

    Callers that have to wait are served in arrival order. ``max_waiters`` caps how
    many may wait at once; past it ``acquire()`` raises
    :class:`~saprfclib.PoolOverloadedError` at once. ``None`` (the default) leaves the
    queue unbounded; ``0`` means never wait.
    """

    def __init__(
        self,
        params: dict[str, Any],
        min_size: int = 1,
        max_size: int = 10,
        *,
        reset_on_release: bool = False,
        max_waiters: int | None = None,
    ) -> None:
        _check_sizes(min_size, max_size, max_waiters)

        self._params: dict[str, Any] = dict(params)
        self._max_size = max_size
        self._max_waiters = max_waiters
        # Reset the ABAP session state before a connection goes back to the idle set
        # (#68), so the next borrower does not inherit function-group globals, buffers
        # or an uncommitted LUW. Off by default: it costs one round trip per release.
        self._reset_on_release = reset_on_release
        # One descriptor cache for the whole pool. A FunctionDesc describes the
        # system, not the socket it arrived over, so a per-connection cache made
        # a pool of N connections pay N round-trips to learn each interface. The
        # key hint covers the case where the system reports no sys_id: these
        # connections are opened from identical parameters, so they reach the
        # same system by construction and may share a bucket.
        self._metadata_cache = MetadataCache()
        self._metadata_cache_key = f"\x00pool-{uuid.uuid4().hex}"
        # The metadata generation each connection's ABAP session last loaded under
        # (#80). An ABAP session keeps the function groups it has loaded: after an
        # interface change it still runs the old version, and reads a longer value
        # cut to the old length without an error (live probe, docs/protocol/
        # framing.md "Metadata and the server's loaded version"). So after
        # invalidate_metadata() a connection loaded before it is reset before it is
        # lent again. Connections the pool did not open itself count as current.
        self._loaded: dict[Any, int] = {}
        self._cv = threading.Condition()
        self._idle: deque[Any] = deque()
        self._in_use: set[Any] = set()
        # Callers waiting for a connection, oldest first; each waits on its own Event.
        # Only the head may take a connection, so service follows arrival (#84).
        self._waiters: deque[threading.Event] = deque()
        self._created = 0
        self._closed = False
        self.metrics = PoolMetrics()

        # Warm-up (POOL-01): pre-open min_size connections before any acquire.
        for _ in range(min_size):
            generation = self._metadata_cache.generation
            conn = self._open()
            self._loaded[conn] = generation
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
        return _connection.connect(
            **self._params,
            metadata_cache=self._metadata_cache,
            metadata_cache_key=self._metadata_cache_key,
        )

    def _ping_ok(self, conn: Any) -> bool:
        """True iff ``conn.ping()`` reports liveness. Any False/exception is dead.

        Called OUTSIDE the Condition lock (Pitfall 2). Treats both a falsy ping
        result and any raised exception as a dead connection.
        """
        if _is_retired(conn):
            _logger.debug("pool: discarding a connection whose session is BROKEN")
            return False
        generation = self._metadata_cache.generation
        if self._loaded.get(conn, generation) != generation:
            # Loaded before an invalidate_metadata(): reset instead of pinging. The
            # reset is a round trip as well, so it is the health check too.
            try:
                conn.reset_server_context()
            except Exception as exc:  # noqa: BLE001 — any failure means "do not lend it"
                _logger.debug(
                    "pool: discarding a connection whose context reset failed (%s: %s)",
                    type(exc).__name__,
                    exc,
                )
                return False
            self._loaded[conn] = generation
            return True
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
        self._loaded.pop(conn, None)
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
        """Check out a healthy connection, or raise on the deadline or an overload.

        Predicate loop under the Condition's lock (D-13). A caller may take a
        connection only when nobody is queued ahead of it (#84):

          1. Reuse an idle connection, ping-checked OUTSIDE the lock (Pitfall 2):
             pop under lock + provisionally count out, release lock, ping, then
             re-acquire to lend (healthy) or discard+replace (dead, POOL-03).
          2. Otherwise lazily grow toward max_size (POOL-01).
          3. Otherwise join the back of the waiter queue (or raise
             PoolOverloadedError if ``max_waiters`` are already queued) and wait on
             this caller's own Event until it is woken at the head or the deadline.

        A caller whose idle connection fails its health check goes back to the
        *front* of the queue: it was next in line, and losing its place to a dead
        connection would make it pay for the pool's churn.
        """
        started = time.monotonic()
        deadline = started + timeout
        discarded = 0
        me: threading.Event | None = None
        with self._cv:
            try:
                while True:
                    if self._closed:
                        raise RuntimeError("pool is closed")

                    first_in_line = not self._waiters if me is None else self._waiters[0] is me
                    if first_in_line and (self._idle or self._created < self._max_size):
                        if me is not None:
                            self._waiters.popleft()
                            me = None

                        # 1) Reuse an idle connection, ping-checked outside the lock.
                        if self._idle:
                            candidate = self._idle.popleft()
                            # Provisionally mark it out so no other thread can grab it
                            # and so _created accounting stays consistent across the
                            # lock gap.
                            self._in_use.add(candidate)
                            # Another connection may be free for the next in line.
                            self._wake_head()
                            self._cv.release()
                            try:
                                healthy = self._ping_ok(candidate)
                            finally:
                                self._cv.acquire()
                            if healthy:
                                self.metrics.hits += 1
                                self.metrics.acquires += 1
                                self.metrics._record_wait(time.monotonic() - started)
                                return candidate
                            # Dead connection: discard + replace (POOL-03).
                            self._in_use.discard(candidate)
                            self._created -= 1
                            discarded += 1
                            self.metrics.discards += 1
                            # Keep this caller's place at the front of the queue.
                            me = threading.Event()
                            self._waiters.appendleft(me)
                            self._cv.release()
                            try:
                                self._safe_close(candidate)
                            finally:
                                self._cv.acquire()
                            continue

                        # 2) Lazily grow toward max_size.
                        self._created += 1
                        self.metrics.creates += 1
                        self._wake_head()
                        generation = self._metadata_cache.generation
                        self._cv.release()
                        try:
                            fresh = self._open()
                        except BaseException:
                            # Open failed: undo the reservation and surface the error.
                            self._cv.acquire()
                            self._created -= 1
                            # The reservation is undone, so the create never happened.
                            # Leaving it counted would show a pool steadily opening
                            # connections that do not exist.
                            self.metrics.creates -= 1
                            self._wake_head()
                            raise
                        else:
                            self._cv.acquire()
                        self._loaded[fresh] = generation
                        self._in_use.add(fresh)
                        self.metrics.acquires += 1
                        self.metrics._record_wait(time.monotonic() - started)
                        return fresh

                    # 3) Nothing to take now: queue up, then wait for a turn or the
                    # deadline.
                    if me is None:
                        if (
                            self._max_waiters is not None
                            and len(self._waiters) >= self._max_waiters
                        ):
                            self.metrics.overloads += 1
                            raise PoolOverloadedError(
                                waiters=len(self._waiters),
                                max_waiters=self._max_waiters,
                                active=len(self._in_use),
                                idle=len(self._idle),
                                max_size=self._max_size,
                            )
                        me = threading.Event()
                        self._waiters.append(me)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.metrics.timeouts += 1
                        self.metrics._record_wait(time.monotonic() - started)
                        raise PoolTimeoutError(
                            waited=timeout,
                            discarded=discarded,
                            active=len(self._in_use),
                            idle=len(self._idle),
                            max_size=self._max_size,
                        )
                    # Cleared under the lock, after the state was checked: a wake-up
                    # is only ever set under the same lock, so none can be lost
                    # between this check and the wait below.
                    me.clear()
                    self._cv.release()
                    try:
                        me.wait(remaining)
                    finally:
                        self._cv.acquire()
            finally:
                if me is not None:
                    # Leaving the queue without a connection (deadline, close, or an
                    # error): pass the turn on, or the caller behind would wait for a
                    # wake-up that was meant for this one.
                    self._waiters.remove(me)
                    self._wake_head()

    def _wake_head(self) -> None:
        """Wake the caller at the head of the queue. Call with the lock held."""
        if self._waiters:
            self._waiters[0].set()

    def release(self, conn: Any) -> None:
        """Return a lent connection to the idle set and wake the next waiter (POOL-04).

        With ``reset_on_release`` the server context is reset first, outside the lock
        (it is a round trip). A connection whose reset fails, or that has already
        retired itself, is closed instead of being returned.
        """
        discard = self._reset_failed(conn) or _is_retired(conn)
        with self._cv:
            self._in_use.discard(conn)
            if discard and not self._closed:
                self.metrics.discards += 1
            if self._closed or discard:
                # Pool shut down while this connection was out: close it instead of
                # returning it to a defunct idle set.
                self._created -= 1
                self._cv.release()
                try:
                    self._safe_close(conn)
                finally:
                    self._cv.acquire()
                self._wake_head()
                return
            self._idle.append(conn)
            self._wake_head()

    def _reset_failed(self, conn: Any) -> bool:
        """Reset the connection's server context if configured; True if that failed."""
        if not self._reset_on_release or self._closed or _is_retired(conn):
            return False
        generation = self._metadata_cache.generation
        try:
            conn.reset_server_context()
        except Exception as exc:  # noqa: BLE001 — any failure means "do not lend it again"
            _logger.debug(
                "pool: discarding a connection whose context reset failed (%s: %s)",
                type(exc).__name__,
                exc,
            )
            return True
        self._loaded[conn] = generation
        return False

    # ------------------------------------------------------------------ #
    # Live gauges                                                        #
    # ------------------------------------------------------------------ #

    @property
    def in_use(self) -> int:
        """Connections currently lent out."""
        return len(self._in_use)

    @property
    def idle(self) -> int:
        """Connections sitting in the pool, ready to lend."""
        return len(self._idle)

    @property
    def size(self) -> int:
        """Connections the pool currently owns, lent or idle."""
        return self._created

    @property
    def max_size(self) -> int:
        """The ceiling the pool will not grow past."""
        return self._max_size

    @property
    def waiting(self) -> int:
        """Callers queued for a connection right now (#84)."""
        return len(self._waiters)

    @property
    def max_waiters(self) -> int | None:
        """How many callers may queue before acquire() raises PoolOverloadedError."""
        return self._max_waiters

    def stats(self) -> dict[str, float | int]:
        """Counters and live gauges together, flat, for an exporter.

        The gauges are read without the lock. They are a snapshot either way --
        by the time a caller acts on them another thread may have acquired or
        released -- so taking the lock would buy a consistency that cannot
        survive the return statement, at the cost of contending with the acquire
        path this is meant to observe.
        """
        return {
            **self.metrics.as_dict(),
            "in_use": self.in_use,
            "idle": self.idle,
            "size": self.size,
            "max_size": self.max_size,
            "waiting": self.waiting,
        }

    def invalidate_metadata(self, name: str | None = None) -> int:
        """Forget cached function metadata for every connection in the pool (#80).

        The pool's connections share one descriptor cache, so this clears it for
        all of them, lent or idle; each refetches the interface (and the DDIC type
        layouts it uses) on its next call. ``name`` forgets one function module,
        ``None`` everything. Returns how many descriptors were dropped.

        A server session keeps running the version of a function group it loaded
        before the change, so every connection is also reset
        (``reset_server_context()``) before it is next lent, in place of its health
        check; one whose reset fails is discarded. That drops whatever ABAP session
        state those connections held. A connection lent right now finishes its
        current work on the old version and is reset when it is next lent.
        """
        return self._metadata_cache.invalidate(name)

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
            # Every waiter wakes, sees the pool closed and leaves.
            for waiter in self._waiters:
                waiter.set()
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
        *,
        reset_on_release: bool = False,
        max_waiters: int | None = None,
    ) -> None:
        _check_sizes(min_size, max_size, max_waiters)

        self._params: dict[str, Any] = dict(params)
        self._max_size = max_size
        self._max_waiters = max_waiters
        # Reset the ABAP session state before a connection goes back to the idle set
        # (#68), so the next borrower does not inherit function-group globals, buffers
        # or an uncommitted LUW. Off by default: it costs one round trip per release.
        self._reset_on_release = reset_on_release
        self._min_size = min_size
        # Single asyncio.Condition guards ALL pool state (idle deque, in_use set,
        # _created counter).  Its underlying asyncio.Lock is the boundary for
        # pool mutations; the Condition is used for wait/notify on exhaustion.
        self._cond: asyncio.Condition = asyncio.Condition()
        self._idle: deque[Any] = deque()
        self._in_use: set[Any] = set()
        # Tasks waiting for a connection, oldest first, each on its own Event; only
        # the head may take one (#84), as in ConnectionPool.
        self._waiters: deque[asyncio.Event] = deque()
        self._created = 0
        self._metadata_cache = MetadataCache()
        self._metadata_cache_key = f"\x00pool-{uuid.uuid4().hex}"
        # The metadata generation each connection's ABAP session last loaded under
        # (#80). An ABAP session keeps the function groups it has loaded: after an
        # interface change it still runs the old version, and reads a longer value
        # cut to the old length without an error (live probe, docs/protocol/
        # framing.md "Metadata and the server's loaded version"). So after
        # invalidate_metadata() a connection loaded before it is reset before it is
        # lent again. Connections the pool did not open itself count as current.
        self._loaded: dict[Any, int] = {}
        # Cumulative, not per-checkout: _checkout runs inside a wait_for, so a
        # timeout unwinds it and any counter local to it is lost with the frame.
        # acquire() snapshots this before and after to get the per-wait figure.
        self._discarded_total = 0
        self.metrics = PoolMetrics()
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
            generation = self._metadata_cache.generation
            conn = await self._open()
            self._loaded[conn] = generation
            async with self._cond:
                self._idle.append(conn)
                self._created += 1
                self._wake_head()

    # ------------------------------------------------------------------ #
    # Connection lifecycle seams (all real async I/O touch points)
    # ------------------------------------------------------------------ #

    async def _open(self) -> Any:
        """Open a fresh AsyncConnection via the connect_async() factory seam (D-10).

        Dispatches through the ``saprfclib.connection`` module attribute (not a
        bound name) so the factory seam stays patchable for offline tests —
        mirrors ConnectionPool._open().
        """
        return await _connection.connect_async(
            **self._params,
            metadata_cache=self._metadata_cache,
            metadata_cache_key=self._metadata_cache_key,
        )

    async def _ping_ok(self, conn: Any) -> bool:
        """True iff ``await conn.ping()`` reports liveness.  Called OUTSIDE the lock.

        Any ``Exception`` (including CommunicationError) means the connection is
        dead.  ``asyncio.CancelledError`` is ``BaseException`` and propagates
        without being caught (Pitfall 7 — never swallow cancellation).
        """
        if _is_retired(conn):
            _logger.debug("pool: discarding a connection whose session is BROKEN")
            return False
        generation = self._metadata_cache.generation
        if self._loaded.get(conn, generation) != generation:
            # Loaded before an invalidate_metadata(): reset instead of pinging, as in
            # ConnectionPool._ping_ok.
            try:
                await conn.reset_server_context()
            except Exception as exc:  # noqa: BLE001 — any failure means "do not lend it"
                _logger.debug(
                    "pool: discarding a connection whose context reset failed (%s: %s)",
                    type(exc).__name__,
                    exc,
                )
                return False
            self._loaded[conn] = generation
            return True
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
        self._loaded.pop(conn, None)
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
        started = time.monotonic()
        try:
            conn = await asyncio.wait_for(self._checkout(), timeout=timeout)
        except TimeoutError as exc:
            async with self._cond:
                self.metrics.timeouts += 1
                self.metrics._record_wait(time.monotonic() - started)
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
        self.metrics.acquires += 1
        self.metrics._record_wait(time.monotonic() - started)
        try:
            yield conn
        finally:
            await self.release(conn)

    async def _checkout(self) -> Any:
        """Check out a healthy connection or raise on close; ping OUTSIDE the lock (Pitfall 2).

        Mirrors ConnectionPool._checkout, including its arrival-order queue (#84):

        1. First in line and an idle connection: pop it under the Condition,
           release the lock, ``await ping``: healthy → return; dead → discard and
           go back to the front of the queue (POOL-03).
        2. First in line and room to grow: reserve a slot under the lock, then
           ``await _open()`` outside it.
        3. Otherwise join the back of the queue (or raise PoolOverloadedError at
           ``max_waiters``) and wait on this task's own Event.

        It runs inside ``asyncio.wait_for``, so a timeout arrives as a cancellation
        at any ``await``. Each await below therefore undoes what it reserved before
        the cancellation propagates: an unread ping reply or a half-open socket
        must not stay counted as a lent or a created connection.
        """
        me: asyncio.Event | None = None
        try:
            while True:
                candidate = None
                reserved = False
                async with self._cond:
                    if self._closed:
                        raise RuntimeError("pool is closed")
                    first_in_line = not self._waiters if me is None else self._waiters[0] is me
                    if first_in_line and (self._idle or self._created < self._max_size):
                        if me is not None:
                            self._waiters.popleft()
                            me = None
                        if self._idle:
                            # 1) Reuse an idle connection, ping-checked outside the lock.
                            candidate = self._idle.popleft()
                            self._in_use.add(candidate)
                        else:
                            # 2) Reserve a slot and open outside the lock.
                            self._created += 1
                            self.metrics.creates += 1
                            reserved = True
                        # Another connection may be free for the next in line.
                        self._wake_head()
                    else:
                        # 3) Queue up.
                        if me is None:
                            if (
                                self._max_waiters is not None
                                and len(self._waiters) >= self._max_waiters
                            ):
                                self.metrics.overloads += 1
                                raise PoolOverloadedError(
                                    waiters=len(self._waiters),
                                    max_waiters=self._max_waiters,
                                    active=len(self._in_use),
                                    idle=len(self._idle),
                                    max_size=self._max_size,
                                )
                            me = asyncio.Event()
                            self._waiters.append(me)
                        # Cleared under the lock after the state was checked; every
                        # set() happens under it too, so no wake-up is lost before
                        # the wait below.
                        me.clear()

                # ---- Outside the Condition lock — do async I/O here ---- #
                if candidate is not None:
                    try:
                        healthy = await self._ping_ok(candidate)
                    except BaseException:
                        # Cancelled mid-ping: the reply may be unread, so the
                        # connection cannot be lent again. No await before the
                        # bookkeeping, so it cannot be interrupted.
                        self._drop(candidate)
                        await self._safe_close(candidate)
                        raise
                    if healthy:
                        self.metrics.hits += 1
                        return candidate
                    # Dead connection: discard + replace (POOL-03), keeping this
                    # task's place at the front of the queue.
                    self._drop(candidate)
                    me = asyncio.Event()
                    self._waiters.appendleft(me)
                    me.set()
                    await self._safe_close(candidate)
                elif reserved:
                    generation = self._metadata_cache.generation
                    try:
                        fresh = await self._open()
                    except BaseException:
                        # Open failed or was cancelled: undo the reservation. The
                        # create never happened, so it is not counted either.
                        self._created -= 1
                        self.metrics.creates -= 1
                        self._wake_head()
                        raise
                    self._loaded[fresh] = generation
                    self._in_use.add(fresh)
                    return fresh
                else:
                    assert me is not None
                    await me.wait()
        finally:
            if me is not None:
                # Leaving the queue without a connection (timeout, close, error):
                # pass the turn on to the task behind.
                self._waiters.remove(me)
                self._wake_head()

    def _drop(self, conn: Any) -> None:
        """Forget a lent connection that will be closed, and wake the next waiter.

        No await, so in asyncio it runs without interruption and needs no lock.
        """
        self._in_use.discard(conn)
        self._created -= 1
        self._discarded_total += 1
        self.metrics.discards += 1
        self._wake_head()

    def _wake_head(self) -> None:
        """Wake the task at the head of the queue."""
        if self._waiters:
            self._waiters[0].set()

    async def release(self, conn: Any) -> None:
        """Return a lent connection to the idle set and wake the next waiter (POOL-04).

        If the pool was closed while the connection was out, close it instead of
        returning it to a defunct idle set.
        """
        discard = await self._reset_failed(conn) or _is_retired(conn)
        close_it = False
        async with self._cond:
            self._in_use.discard(conn)
            if self._closed or discard:
                # Pool shut down while this connection was lent, or the connection
                # cannot be lent again: close it on release.
                if discard and not self._closed:
                    self.metrics.discards += 1
                    self._discarded_total += 1
                self._created -= 1
                self._wake_head()
                close_it = True
            else:
                self._idle.append(conn)
                self._wake_head()
        if close_it:
            await self._safe_close(conn)

    async def _reset_failed(self, conn: Any) -> bool:
        """Reset the connection's server context if configured; True if that failed."""
        if not self._reset_on_release or self._closed or _is_retired(conn):
            return False
        generation = self._metadata_cache.generation
        try:
            await conn.reset_server_context()
        except Exception as exc:  # noqa: BLE001 — any failure means "do not lend it again"
            _logger.debug(
                "pool: discarding a connection whose context reset failed (%s: %s)",
                type(exc).__name__,
                exc,
            )
            return True
        self._loaded[conn] = generation
        return False

    # ------------------------------------------------------------------ #
    # Live gauges                                                        #
    # ------------------------------------------------------------------ #

    @property
    def in_use(self) -> int:
        """Connections currently lent out."""
        return len(self._in_use)

    @property
    def idle(self) -> int:
        """Connections sitting in the pool, ready to lend."""
        return len(self._idle)

    @property
    def size(self) -> int:
        """Connections the pool currently owns, lent or idle."""
        return self._created

    @property
    def max_size(self) -> int:
        """The ceiling the pool will not grow past."""
        return self._max_size

    @property
    def waiting(self) -> int:
        """Callers queued for a connection right now (#84)."""
        return len(self._waiters)

    @property
    def max_waiters(self) -> int | None:
        """How many callers may queue before acquire() raises PoolOverloadedError."""
        return self._max_waiters

    def stats(self) -> dict[str, float | int]:
        """Counters and live gauges together, flat, for an exporter.

        The gauges are read without the lock. They are a snapshot either way --
        by the time a caller acts on them another thread may have acquired or
        released -- so taking the lock would buy a consistency that cannot
        survive the return statement, at the cost of contending with the acquire
        path this is meant to observe.
        """
        return {
            **self.metrics.as_dict(),
            "in_use": self.in_use,
            "idle": self.idle,
            "size": self.size,
            "max_size": self.max_size,
            "waiting": self.waiting,
        }

    def invalidate_metadata(self, name: str | None = None) -> int:
        """Forget cached function metadata for every connection in the pool (#80).

        The pool's connections share one descriptor cache, so this clears it for
        all of them, lent or idle; each refetches the interface (and the DDIC type
        layouts it uses) on its next call. ``name`` forgets one function module,
        ``None`` everything. Returns how many descriptors were dropped.

        A server session keeps running the version of a function group it loaded
        before the change, so every connection is also reset
        (``reset_server_context()``) before it is next lent, in place of its health
        check; one whose reset fails is discarded. That drops whatever ABAP session
        state those connections held. A connection lent right now finishes its
        current work on the old version and is reset when it is next lent.
        """
        return self._metadata_cache.invalidate(name)

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
            # Every waiter wakes, sees the pool closed and leaves.
            for waiter in self._waiters:
                waiter.set()
        # Close outside the lock (close may do async I/O).
        for conn in idle_conns:
            await self._safe_close(conn)
