# tests/test_phase05_pool.py
#
# Offline unit + property tests for the thread-safe ConnectionPool (Plan 05-01,
# POOL-01..04 + PoolTimeoutError). ZERO sockets: the pool's connection factory
# (saprfclib.connection.connect) is patched to mint LendableConnection doubles whose
# ping() returns scripted booleans, so warm-up, single-owner lend, ping-before-
# lend discard/replace, exhaustion timeout, and concurrent invariants are all
# exercised without a live SAP system.
#
# Idiom mirrors tests/test_connection.py's _ready_connection() helper: a small
# scripted Connection double instead of a MockTransport-driven real Connection,
# since the pool only ever touches ping()/close() on what it lends.
#
# Security: no credentials are ever logged or placed in assertion messages
# (threat T-04-CRED / T-05-P03).

import threading

import pytest

from saprfclib.exceptions import PoolTimeoutError
from saprfclib.pool import ConnectionPool


# --------------------------------------------------------------------------- #
# Lendable connection double
# --------------------------------------------------------------------------- #
class LendableConnection:
    """A scripted Connection stand-in the pool can lend, ping, and close.

    ``ping_results`` is an iterable of booleans (or exceptions) consumed FIFO by
    successive ``ping()`` calls; once exhausted, ping() returns True (healthy).
    Each instance carries a unique ``conn_id`` so tests can assert single-owner
    (distinct-object) lend semantics. ``close()`` flips ``closed`` to True.
    """

    _counter = 0
    _counter_lock = threading.Lock()

    def __init__(self, ping_results=None):
        with LendableConnection._counter_lock:
            LendableConnection._counter += 1
            self.conn_id = LendableConnection._counter
        self._ping_results = list(ping_results) if ping_results else []
        self.closed = False
        self.ping_calls = 0

    def ping(self) -> bool:
        self.ping_calls += 1
        if self._ping_results:
            result = self._ping_results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return True

    def close(self) -> None:
        self.closed = True


def _lendable_connection(ping_results=None) -> LendableConnection:
    """Build a single scripted LendableConnection (mirrors _ready_connection)."""
    return LendableConnection(ping_results=ping_results)


def _patch_factory(monkeypatch, factory):
    """Patch the pool's connection factory seam so _open() mints doubles.

    The pool's _open() calls saprfclib.connection.connect(**params); patching that
    symbol keeps the pool wholly offline. ``factory`` is a zero-arg callable
    returning the next connection double.
    """
    import saprfclib.connection as connection_mod

    def _fake_connect(*args, **kwargs):
        return factory()

    monkeypatch.setattr(connection_mod, "connect", _fake_connect)


_PARAMS = {
    "ashost": "test.example",
    "sysnr": "00",
    "client": "001",
    "user": "TESTER",
    "passwd": "ignored-by-fake-connect",
}


# --------------------------------------------------------------------------- #
# POOL-01: warm-up
# --------------------------------------------------------------------------- #
def test_pool_init_warms_min_size(monkeypatch) -> None:
    """A pool built with min_size=2 opens exactly 2 connections before any acquire."""
    opened: list[LendableConnection] = []

    def factory():
        c = _lendable_connection()
        opened.append(c)
        return c

    _patch_factory(monkeypatch, factory)
    pool = ConnectionPool(_PARAMS, min_size=2, max_size=10)
    try:
        assert len(opened) == 2
    finally:
        pool.close()


# --------------------------------------------------------------------------- #
# POOL-02: single-owner lend
# --------------------------------------------------------------------------- #
def test_acquire_never_double_lends(monkeypatch) -> None:
    """Two acquires without release between hand out two DISTINCT connections;
    the same object is never lent twice while in use."""

    def factory():
        return _lendable_connection()

    _patch_factory(monkeypatch, factory)
    pool = ConnectionPool(_PARAMS, min_size=2, max_size=4)
    try:
        with pool.acquire(timeout=1.0) as a:
            with pool.acquire(timeout=1.0) as b:
                assert a is not b
                assert a.conn_id != b.conn_id
    finally:
        pool.close()


# --------------------------------------------------------------------------- #
# POOL-03: discard + replace on failed ping
# --------------------------------------------------------------------------- #
def test_ping_fail_discards_and_replaces(monkeypatch) -> None:
    """A pooled connection whose ping() returns False is closed and replaced; the
    caller still receives a healthy connection."""
    # First connection minted is sick (ping -> False); all later ones are healthy.
    sick = _lendable_connection(ping_results=[False])
    minted: list[LendableConnection] = [sick]

    def factory():
        if minted:
            return minted.pop(0)
        return _lendable_connection()  # healthy replacement

    _patch_factory(monkeypatch, factory)
    pool = ConnectionPool(_PARAMS, min_size=1, max_size=4)
    try:
        with pool.acquire(timeout=1.0) as conn:
            # The sick connection must NOT be lent; a fresh healthy one is.
            assert conn is not sick
        assert sick.closed is True
    finally:
        pool.close()


# --------------------------------------------------------------------------- #
# POOL (timeout): exhaustion raises PoolTimeoutError with diagnostics
# --------------------------------------------------------------------------- #
def test_pool_exhaustion_raises_timeout(monkeypatch) -> None:
    """When max_size connections are all in use, acquire(timeout=short) raises
    PoolTimeoutError whose message carries waited, discarded, and active/idle/max."""

    def factory():
        return _lendable_connection()

    _patch_factory(monkeypatch, factory)
    pool = ConnectionPool(_PARAMS, min_size=1, max_size=1)
    try:
        with pool.acquire(timeout=1.0):
            # Pool is now exhausted (max_size=1, one in use).
            with pytest.raises(PoolTimeoutError) as excinfo:
                pool.acquire(timeout=0.05).__enter__()
            err = excinfo.value
            assert err.max_size == 1
            assert err.active == 1
            assert err.idle == 0
            assert err.waited >= 0.0
            msg = str(err)
            assert "max=1" in msg
            assert "active=1" in msg
            assert "idle=0" in msg
            assert "discarded=" in msg
    finally:
        pool.close()


# --------------------------------------------------------------------------- #
# POOL-04: concurrent acquire/release invariants (Hypothesis)
# --------------------------------------------------------------------------- #
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(
    n_threads=st.integers(min_value=2, max_value=8),
    max_size=st.integers(min_value=1, max_value=4),
)
def test_concurrent_acquire_release_invariants(n_threads, max_size) -> None:
    """Under N concurrent threads doing acquire-then-release, invariants hold:
    len(in_use) <= max_size at all times, no connection is simultaneously idle and
    in_use, every acquired connection is released, and there is no deadlock."""

    def factory():
        return _lendable_connection()

    import saprfclib.connection as connection_mod

    def _fake_connect(*args, **kwargs):
        return factory()

    # Cannot use monkeypatch fixture inside @given (function-scoped fixture); patch
    # manually and restore in finally.
    original_connect = connection_mod.connect
    connection_mod.connect = _fake_connect
    try:
        pool = ConnectionPool(_PARAMS, min_size=1, max_size=max_size)
        violations: list[str] = []
        barrier = threading.Barrier(n_threads)

        def worker():
            barrier.wait()
            for _ in range(5):
                try:
                    with pool.acquire(timeout=2.0) as conn:
                        # Invariant: total in_use never exceeds max_size, and the
                        # connection we hold is not also sitting in the idle set.
                        with pool._cv:
                            if len(pool._in_use) > max_size:
                                violations.append(f"in_use={len(pool._in_use)} > max={max_size}")
                            if conn in pool._idle:
                                violations.append("lent connection also in idle set")
                            if conn not in pool._in_use:
                                violations.append("lent connection missing from in_use")
                except PoolTimeoutError:
                    # Acceptable under contention with a generous timeout; not a
                    # correctness violation. (Should be rare with timeout=2.0.)
                    pass

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        # No deadlock: every worker thread finished.
        assert all(not t.is_alive() for t in threads), "deadlock: a worker hung"
        assert not violations, f"pool invariant violations: {violations}"

        # After all release: nothing left in_use; idle/in_use are disjoint.
        with pool._cv:
            assert len(pool._in_use) == 0
            assert set(pool._idle).isdisjoint(pool._in_use)
        pool.close()
    finally:
        connection_mod.connect = original_connect
