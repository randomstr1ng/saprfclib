# SPDX-License-Identifier: MPL-2.0
"""Per-connection call metrics (#22).

duration_s and the byte counts are measured locally — our clock, our socket.
server_duration_s comes from the server itself, tag 0x0667 of the response, now
that a behavioural probe has settled what that field counts: the server-side
duration of the answered call, in microseconds, per call. It is the one number
that separates server time from network time. See tests/test_server_duration.py
and docs/protocol/framing.md.
"""

from __future__ import annotations

import socket

import pytest

from saprfclib import CallStats, ConnectionMetrics
from saprfclib.transport import Transport, build_ni_frame


def test_metrics_start_at_zero() -> None:
    m = ConnectionMetrics()
    assert m.calls == 0
    assert m.failures == 0
    # A mean over no samples must be 0.0, not a ZeroDivisionError.
    assert m.mean_duration_s == 0.0


def test_totals_accumulate() -> None:
    m = ConnectionMetrics()
    m.record(CallStats("A", 0.10, 100, 1000))
    m.record(CallStats("B", 0.30, 200, 2000))
    assert m.calls == 2
    assert m.total_duration_s == pytest.approx(0.40)
    assert m.mean_duration_s == pytest.approx(0.20)
    assert m.max_duration_s == pytest.approx(0.30)
    assert m.request_bytes == 300
    assert m.response_bytes == 3000
    assert m.last is not None and m.last.func_name == "B"


def test_failures_are_counted_and_still_timed() -> None:
    """A view that counts only successes hides the trend worth alerting on.

    If a system starts failing slowly, success-only latency looks unchanged
    while every user waits — the failures are where the signal is.
    """
    m = ConnectionMetrics()
    m.record(CallStats("OK", 0.1, 10, 10))
    m.record(CallStats("BOOM", 5.0, 10, 0, failed=True))
    assert m.calls == 2
    assert m.failures == 1
    assert m.max_duration_s == pytest.approx(5.0)
    assert m.total_duration_s == pytest.approx(5.1)


def test_no_unbounded_sample_list() -> None:
    """Latency is a total plus a count, so a long-lived connection cannot leak.

    Keeping every sample would be a slow memory leak on a pooled connection that
    lives for weeks.
    """
    m = ConnectionMetrics()
    for _ in range(50_000):
        m.record(CallStats("F", 0.001, 1, 1))
    assert m.calls == 50_000
    assert not hasattr(m, "__dict__"), "__slots__ keeps the footprint fixed"
    assert set(ConnectionMetrics.__slots__) == {
        "total_server_duration_s",
        "server_timed_calls",
        "calls",
        "failures",
        "total_duration_s",
        "max_duration_s",
        "request_bytes",
        "response_bytes",
        "last",
    }


def test_as_dict_is_flat_and_json_ready() -> None:
    """Shaped for an exporter: no nesting, no objects."""
    import json

    m = ConnectionMetrics()
    m.record(CallStats("A", 0.25, 100, 200))
    d = m.as_dict()
    assert set(d) == {
        "total_server_duration_s",
        "mean_server_duration_s",
        "server_timed_calls",
        "server_time_fraction",
        "calls",
        "failures",
        "total_duration_s",
        "mean_duration_s",
        "max_duration_s",
        "request_bytes",
        "response_bytes",
    }
    assert all(isinstance(v, (int, float)) for v in d.values())
    json.dumps(d)


def test_call_stats_is_immutable() -> None:
    """A recorded measurement must not be editable after the fact."""
    import dataclasses

    stats = CallStats("A", 0.1, 1, 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        stats.duration_s = 9.9  # type: ignore[misc]


def test_transport_counts_wire_bytes_including_the_ni_prefix() -> None:
    """Byte counts must match a packet capture, not the payload the RFC layer sees."""
    a, b = socket.socketpair()
    try:
        t = Transport(a)
        assert t.bytes_sent == 0 and t.bytes_received == 0

        t.send_message(b"hello")
        assert t.bytes_sent == 4 + 5, "4-byte NI length prefix must be included"

        b.sendall(build_ni_frame(b"worldworld"))
        assert t.recv_message() == b"worldworld"
        assert t.bytes_received == 4 + 10
    finally:
        a.close()
        b.close()


def test_byte_counters_are_cumulative_so_per_call_deltas_work() -> None:
    """call() takes a before/after difference, which needs monotonic counters."""
    a, b = socket.socketpair()
    try:
        t = Transport(a)
        t.send_message(b"x")
        first = t.bytes_sent
        t.send_message(b"yy")
        assert t.bytes_sent == first + 4 + 2
        assert t.bytes_sent > first, "counters must accumulate, not reset per call"
    finally:
        a.close()
        b.close()


def test_connection_exposes_metrics() -> None:
    """The facade must surface the same object the async core records into."""
    from saprfclib.connection import AsyncConnection, Connection

    assert isinstance(Connection.metrics, property)
    conn = Connection.__new__(Connection)
    conn._async_conn = None
    conn._metrics = ConnectionMetrics()
    assert conn.metrics is conn._metrics

    core = AsyncConnection.__new__(AsyncConnection)
    core.metrics = ConnectionMetrics()
    conn._async_conn = core
    assert conn.metrics is core.metrics, "must not report a second, empty set of numbers"


def test_server_time_averages_over_the_calls_that_reported_one() -> None:
    """Not over every call. The distinction is the whole point of the None.

    A response without tag 0x0667 carries no measurement. Folding it in as zero
    would understate server time by whatever share of the traffic omits the
    field -- and it would do so quietly, since the resulting number is perfectly
    plausible.
    """
    m = ConnectionMetrics()
    m.record(CallStats("A", 1.0, 1, 1, server_duration_s=0.9))
    m.record(CallStats("B", 1.0, 1, 1))  # no server figure in this reply
    m.record(CallStats("C", 1.0, 1, 1, server_duration_s=0.7))

    assert m.calls == 3
    assert m.server_timed_calls == 2
    assert m.total_server_duration_s == pytest.approx(1.6)
    assert m.mean_server_duration_s == pytest.approx(0.8)  # 1.6 / 2, not 1.6 / 3


def test_server_time_fraction_separates_slow_abap_from_slow_network() -> None:
    m = ConnectionMetrics()
    m.record(CallStats("SLOW_ABAP", 1.0, 1, 1, server_duration_s=0.97))
    assert m.server_time_fraction == pytest.approx(0.97)

    n = ConnectionMetrics()
    n.record(CallStats("SLOW_LINK", 1.0, 1, 1, server_duration_s=0.02))
    assert n.server_time_fraction == pytest.approx(0.02)


def test_server_time_fraction_is_zero_when_nothing_was_measured() -> None:
    """And server_timed_calls is what tells a reader which zero this is.

    An unqualified 0.0 would read as "the server is instant" rather than
    "no response carried the field".
    """
    m = ConnectionMetrics()
    m.record(CallStats("A", 1.0, 1, 1))
    assert m.server_time_fraction == 0.0
    assert m.mean_server_duration_s == 0.0
    assert m.server_timed_calls == 0

    empty = ConnectionMetrics()
    assert empty.server_time_fraction == 0.0
    assert empty.mean_server_duration_s == 0.0


def test_the_sync_call_path_records_metrics_too() -> None:
    """Shipped as working in v0.1.3, and silent on two transports.

    Metrics were recorded only in AsyncConnection.call, which classic TCP
    delegates to. The wRFC and SNC paths run Connection.call directly, so a
    ConnectionMetrics on either reported zero calls however many were made -- and
    a counter that is quietly absent is worse than one that is obviously missing,
    because a dashboard showing nothing looks like an idle connection rather than
    a broken metric. It surfaced only when a live wRFC call succeeded and the run
    still printed "0 call(s)".
    """
    from tests.test_connection import _invoke_response_for_stfc, _ready_connection_with_invoke

    conn, _ = _ready_connection_with_invoke([_invoke_response_for_stfc(echo="hi")])
    assert conn.metrics.calls == 0

    conn.call("STFC_CONNECTION", REQUTEXT="hi")

    assert conn.metrics.calls == 1
    assert conn.metrics.failures == 0
    assert conn.metrics.total_duration_s > 0
    assert conn.metrics.last is not None
    assert conn.metrics.last.func_name == "STFC_CONNECTION"


def test_a_failed_sync_call_is_recorded_as_a_failure() -> None:
    """Counting only successes hides the trend worth alerting on."""
    from saprfclib.exceptions import CommunicationError
    from tests.test_connection import _ready_connection_with_invoke

    conn, _ = _ready_connection_with_invoke([])  # no reply scripted -> EOF
    with pytest.raises(CommunicationError):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")

    assert conn.metrics.calls == 1
    assert conn.metrics.failures == 1
    assert conn.metrics.last is not None
    assert conn.metrics.last.failed is True
