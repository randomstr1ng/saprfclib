# SPDX-License-Identifier: MPL-2.0
"""Connection-level failure modes that hang rather than raise.

The failures guarded here share a shape: nothing errors, nothing logs, the call
simply never returns. A wedged SAP work process and a firewall that drops an idle
NAT mapping both look identical to a blocked ``recv`` — which is why they need
socket-level limits rather than application-level checks.
"""

from __future__ import annotations

import socket
import threading

import pytest

from saprfclib.transport import (
    DEFAULT_CONNECT_TIMEOUT,
    Transport,
    connect_tcp,
    enable_keepalive,
)


def _listener() -> tuple[socket.socket, int]:
    """A listening socket that accepts but never speaks — a wedged peer."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    return srv, srv.getsockname()[1]


def test_connect_timeout_has_a_default() -> None:
    """Unbounded by default meant a wedged peer hung the caller forever."""
    assert DEFAULT_CONNECT_TIMEOUT is not None
    assert 0 < DEFAULT_CONNECT_TIMEOUT <= 60


def test_read_timeout_is_separate_from_connect_timeout() -> None:
    """One number cannot express "connect fast, then wait as long as the call needs".

    ``socket.create_connection`` leaves its connect timeout on the socket, where
    it silently becomes the per-read timeout. Passing ``timeout=5`` to be strict
    about connecting would then abort any RFC call running longer than 5s.
    """
    srv, port = _listener()
    try:
        transport = connect_tcp("127.0.0.1", port, connect_timeout=5.0, read_timeout=None)
        try:
            # The connect timeout must NOT have leaked onto the socket.
            assert transport._sock.gettimeout() is None
        finally:
            transport.close()

        transport = connect_tcp("127.0.0.1", port, connect_timeout=5.0, read_timeout=0.25)
        try:
            assert transport._sock.gettimeout() == pytest.approx(0.25)
        finally:
            transport.close()
    finally:
        srv.close()


def test_read_timeout_actually_bounds_a_silent_peer() -> None:
    """A peer that accepts and then says nothing must not block forever."""
    srv, port = _listener()
    accepted: list[socket.socket] = []

    def _accept() -> None:
        conn, _ = srv.accept()
        accepted.append(conn)  # held open, deliberately silent

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    try:
        transport = connect_tcp("127.0.0.1", port, connect_timeout=5.0, read_timeout=0.25)
        try:
            with pytest.raises((TimeoutError, OSError)):
                transport.recv_message()
        finally:
            transport.close()
    finally:
        thread.join(timeout=2)
        for conn in accepted:
            conn.close()
        srv.close()


def test_keepalive_is_enabled_on_a_connection() -> None:
    """Without it, a silently dropped path blocks the next read for ~2h on Linux.

    A stateful firewall or NAT between client and SAP drops an idle mapping and
    tells neither end. The pool's health check only covers acquire time, so an
    idle-then-used connection is exactly the case it cannot catch.
    """
    srv, port = _listener()
    try:
        transport = connect_tcp("127.0.0.1", port)
        try:
            assert transport._sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
        finally:
            transport.close()
    finally:
        srv.close()


def test_nodelay_is_still_set() -> None:
    """RFC frames are small; Nagle would add latency to every call."""
    srv, port = _listener()
    try:
        transport = connect_tcp("127.0.0.1", port)
        try:
            assert transport._sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1
        finally:
            transport.close()
    finally:
        srv.close()


def test_enable_keepalive_survives_a_platform_without_the_timing_knobs() -> None:
    """TCP_KEEPIDLE and friends are platform-specific; the base flag is not.

    Enabling keepalive must never fail merely because a platform spells the
    timing options differently — the flag is what matters, the timings only
    shorten the detection window.
    """
    sock = socket.socket()
    try:
        enable_keepalive(sock)
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    finally:
        sock.close()


def test_legacy_timeout_argument_still_applies_to_both() -> None:
    """Existing callers passing a single `timeout` must keep working."""
    srv, port = _listener()
    try:
        transport = connect_tcp("127.0.0.1", port, timeout=0.5)
        try:
            assert transport._sock.gettimeout() == pytest.approx(0.5)
        finally:
            transport.close()
    finally:
        srv.close()


def test_connect_exposes_both_knobs() -> None:
    """The point of the change: a caller can set them independently."""
    import inspect

    from saprfclib import connect, connect_async

    for fn in (connect, connect_async):
        params = inspect.signature(fn).parameters
        assert "connect_timeout" in params, f"{fn.__name__} does not expose connect_timeout"
        assert params["connect_timeout"].default == DEFAULT_CONNECT_TIMEOUT
    # read_timeout is sync-only: an asyncio caller bounds a read with wait_for
    # around the await, which cancels cleanly, rather than with a socket timeout
    # underneath the event loop.
    assert "read_timeout" in inspect.signature(connect).parameters


def test_transport_still_rejects_an_oversized_frame() -> None:
    """The DoS cap must survive the timeout rework."""
    sock_a, sock_b = socket.socketpair()
    try:
        sock_b.sendall((Transport._MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
        transport = Transport(sock_a)
        with pytest.raises(ValueError, match="DoS guard"):
            transport.recv_message()
    finally:
        sock_a.close()
        sock_b.close()


# --------------------------------------------------------------------------- #
# Metadata cache sharing
# --------------------------------------------------------------------------- #


def test_metadata_cache_is_thread_safe() -> None:
    """It is shared across a pool now, so concurrent writers must not corrupt it."""
    from saprfclib.metadata import MetadataCache
    from saprfclib.types import FunctionDesc

    cache = MetadataCache()
    errors: list[BaseException] = []

    def hammer(worker: int) -> None:
        try:
            for i in range(200):
                name = f"Z_FUNC_{i % 20}"
                cache.put("A4H", FunctionDesc(name=name, parameters=[]))
                got = cache.get("A4H", name)
                assert got is not None and got.name == name
        except BaseException as exc:  # noqa: BLE001 - re-raised in the main thread
            errors.append(exc)

    workers = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=10)
    assert not errors, errors


def test_metadata_cache_does_not_hold_its_lock_across_a_fetch() -> None:
    """Holding it across the round-trip would serialise every first call in a pool.

    The fetch here blocks until a second thread has also entered get_or_fetch.
    If the lock were held for the duration, that second thread could not get in
    and this deadlocks rather than completing.
    """
    from saprfclib.metadata import MetadataCache
    from saprfclib.types import FunctionDesc

    cache = MetadataCache()
    both_inside = threading.Barrier(2, timeout=5)

    def fetch(name: str) -> FunctionDesc:
        both_inside.wait()
        return FunctionDesc(name=name, parameters=[])

    results: list[FunctionDesc] = []

    def worker() -> None:
        results.append(cache.get_or_fetch("A4H", "Z_SLOW", fetch))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive(), "get_or_fetch serialised on the lock across fetch()"
    assert len(results) == 2


def test_pool_shares_one_cache_across_its_connections() -> None:
    """A pool of N connections must not pay N round-trips for the same interface."""
    from saprfclib import pool as pool_mod

    seen: list[dict[str, object]] = []

    class _FakeConn:
        def ping(self) -> bool:
            return True

        def close(self) -> None:
            return None

    def fake_connect(**kwargs: object) -> _FakeConn:
        seen.append(kwargs)
        return _FakeConn()

    original = pool_mod._connection.connect
    pool_mod._connection.connect = fake_connect  # type: ignore[assignment]
    try:
        # min_size=0: the default of 1 pre-fills during __init__, which would
        # open a real socket before the factory seam is in place.
        pool = pool_mod.ConnectionPool({"ashost": "h", "sysnr": 0, "client": "001"}, min_size=0)
        first = pool._open()
        second = pool._open()
    finally:
        pool_mod._connection.connect = original  # type: ignore[assignment]

    assert first is not second
    assert len(seen) == 2
    caches = {id(call["metadata_cache"]) for call in seen}
    assert len(caches) == 1, "each connection got its own cache"
    keys = {call["metadata_cache_key"] for call in seen}
    assert len(keys) == 1, "connections in one pool must share the fallback key"


def test_a_bare_connection_still_gets_its_own_cache() -> None:
    """Sharing is opt-in; nothing is shared globally by accident."""
    from saprfclib.connection import Connection

    a = Connection.__new__(Connection)
    b = Connection.__new__(Connection)
    for conn in (a, b):
        Connection.__init__(conn, None)  # type: ignore[arg-type]
    assert a._cache is not b._cache
    assert a._anon_cache_key is None


# --------------------------------------------------------------------------- #
# SAProuter — refusals must be reported, and unsendable routes must not be sent
# --------------------------------------------------------------------------- #


def test_a_router_refusal_is_reported_at_the_ni_layer() -> None:
    """NI_RTERR means the router will not carry the route.

    Without this check the refusal reaches the session as if it were the frame
    the handshake was waiting for, and is misparsed — so a rejected route
    surfaced as a confusing protocol error several steps later instead of as
    "the router said no". NI control messages are the NI layer's business, which
    is why the check lives in the transport.
    """
    from saprfclib.exceptions import SapRfcError
    from saprfclib.transport import raise_for_ni_error

    # A bare marker with no *ERR* record still reports the refusal.
    with pytest.raises(SapRfcError, match="SAProuter refused the route"):
        raise_for_ni_error(b"NI_RTERR\x00")
    with pytest.raises(SapRfcError, match="permission table"):
        raise_for_ni_error(b"NI_RTERR\x00")

    # A real refusal carries the router's own message, which names the source,
    # the target and the port. Live capture from a SAProuter that denied a route.
    from pathlib import Path

    denied = Path(__file__).parent / "golden" / "router" / "ni_rterr_route_denied.bin"
    with pytest.raises(SapRfcError, match="route permission denied") as excinfo:
        raise_for_ni_error(denied.read_bytes()[4:])
    assert "10.99.99.99" in str(excinfo.value), "the target must be named"
    assert "3300" in str(excinfo.value)


def test_router_refusal_surfaces_through_recv_message() -> None:
    """It must fire on the real read path, not only when called directly."""
    from saprfclib.exceptions import SapRfcError
    from saprfclib.transport import Transport, build_ni_frame

    a, b = socket.socketpair()
    try:
        b.sendall(build_ni_frame(b"NI_RTERR\x00"))
        with pytest.raises(SapRfcError, match="SAProuter refused the route"):
            Transport(a).recv_message()
    finally:
        a.close()
        b.close()


def test_ordinary_frames_are_not_mistaken_for_ni_errors() -> None:
    """No false positives: a normal payload must pass straight through."""
    from saprfclib.transport import Transport, build_ni_frame

    a, b = socket.socketpair()
    try:
        payload = b"**MESSAGE**\x00" + bytes(98)
        b.sendall(build_ni_frame(payload))
        assert Transport(a).recv_message() == payload
    finally:
        a.close()
        b.close()


def test_a_route_password_is_refused_rather_than_dropped() -> None:
    """/P/ is parsed but cannot be transmitted, so the route must not be sent.

    Sending it without the password is not graceful degradation: the router
    refuses, and the caller is left with a rejection they cannot attribute to the
    password they supplied. The position of the password in the NI_ROUTE frame
    has never been captured.
    """
    from saprfclib.router import build_ni_route, parse_route_string

    hops = parse_route_string("/H/router.example.com/S/3299/P/secret")
    assert hops[0].password == "secret"
    with pytest.raises(NotImplementedError, match="hop password"):
        build_ni_route(hops, "10.0.0.1", "3300")


def test_a_route_without_a_password_still_builds() -> None:
    """The guard must not block the ordinary case."""
    from saprfclib.router import build_ni_route, parse_route_string

    hops = parse_route_string("/H/router.example.com/S/3299")
    assert build_ni_route(hops, "10.0.0.1", "3300").startswith(b"NI_ROUTE\x00")
