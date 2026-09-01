# SPDX-License-Identifier: MPL-2.0
"""Tag 0x0667: the server's own duration for the call it is answering.

Settled by behavioural probe against A4H, kernel 793. Two earlier readings were
wrong and the way each was wrong is worth keeping in view.

The golden fixtures disagreed: one called it microseconds, the other an
``[ASSUMED]`` timeout in seconds. Neither could be established from a capture,
which shows ``138.0`` without saying what 138.0 counts.

A first probe varied rows read and watched the value move 400x. That ruled out a
fixed setting -- but its verdict, "it tracks the work, so it is a duration", did
not follow. Rows read moves the server's processing time and the size of the
response together, so a byte counter fitted the numbers exactly as well.

RFC_PING_AND_WAIT separates them: it sleeps a known interval and returns a
constant-size reply. Observed:

    SECONDS   wall        response   0x0667
    0         182.09 ms   236 B         593.0
    1        1036.75 ms   236 B     1001468.0
    3        3038.57 ms   236 B     3001166.0

Response flat, value tracking the sleep to 0.1% as microseconds, and each reading
bracketed by the sleep below and the wall clock above. The numbers below are
those measurements, not invented ones.
"""

from __future__ import annotations

import struct

from saprfclib.invoke import extract_server_duration
from saprfclib.invoke import tlv_record as tr

# The three live readings, in microseconds as they appear on the wire.
PROBE_READINGS = {0: 593.0, 1: 1001468.0, 3: 3001166.0}


def _response_with(micros: float) -> bytes:
    return tr(0x0500, b"") + tr(0x0667, struct.pack("<d", micros)) + struct.pack(">HH", 0xFFFF, 0)


def test_the_probe_readings_decode_to_the_sleeps_that_produced_them() -> None:
    """Microseconds, and seconds on the public surface.

    Read as milliseconds these would be 1000 s and 3000 s -- the reading this
    replaced, and absurd against a 3-second sleep.
    """
    for seconds, micros in PROBE_READINGS.items():
        got = extract_server_duration(_response_with(micros))
        assert got is not None
        assert abs(got - seconds) < 0.01, f"SECONDS={seconds} decoded as {got}"


def test_the_value_is_per_call_not_cumulative() -> None:
    """A running total would have put the third call near 4002634 us.

    It read 3001166 -- its own duration alone. Recorded as an assertion because a
    cumulative reading would look entirely plausible in any single capture, and
    only a sequence disproves it.
    """
    running_total = sum(PROBE_READINGS.values())
    assert PROBE_READINGS[3] < running_total
    assert abs(PROBE_READINGS[3] - 3_000_000.0) < 5_000


def test_absent_is_none_and_not_zero() -> None:
    """The distinction the metrics series depends on.

    No release rule requiring the tag has been established, so a response without
    it means unknown. Zero would enter a latency series as an impossibly fast
    call and drag every average down with a number nothing measured.
    """
    assert extract_server_duration(tr(0x0500, b"")) is None
    assert extract_server_duration(b"") is None


def test_a_wrong_width_is_ignored_rather_than_unpacked() -> None:
    """8 bytes or nothing. A 4-byte field is not a float64 to be reinterpreted."""
    assert extract_server_duration(tr(0x0667, b"\x00\x00\x00\x00")) is None


def test_a_malformed_tail_does_not_lose_the_value_or_raise() -> None:
    """This is a metric, not a result: a timing detail must never fail a call."""
    frame = _response_with(593.0) + b"\xab\xcd\xff\xf0"
    assert extract_server_duration(frame) == 593.0 / 1e6
    # And a frame that is nothing but garbage yields None rather than an exception.
    assert extract_server_duration(b"\xab\xcd\xff\xf0\x01") is None


def test_extended_length_records_are_walked_correctly() -> None:
    """A large table ahead of the tag must not desynchronise the walk."""
    big = b"\x00" * 0x10000
    frame = (
        struct.pack(">HH", 0x0303, 0xFFFF)
        + struct.pack(">I", len(big))
        + big
        + tr(0x0667, struct.pack("<d", 1001468.0))
        + struct.pack(">HH", 0xFFFF, 0)
    )
    got = extract_server_duration(frame)
    assert got is not None and abs(got - 1.0) < 0.01


def test_both_wire_dialects_are_walked() -> None:
    """With and without the repeated close tag after each record.

    Live responses repeat the tag; a reader that does not skip it desynchronises
    by two bytes and reads every subsequent tag and length out of the middle of a
    value. tlv_record already emits the close tag, so the open-only form has to be
    built by hand to be tested at all -- and it is the form the golden fixtures
    for older frames use.
    """
    payload = struct.pack("<d", 3001166.0)

    with_close = tr(0x0500, b"") + tr(0x0667, payload) + struct.pack(">HH", 0xFFFF, 0)
    open_only = (
        struct.pack(">HH", 0x0500, 0)
        + struct.pack(">HH", 0x0667, 8)
        + payload
        + struct.pack(">HH", 0xFFFF, 0)
    )

    for label, frame in (("with close tags", with_close), ("open only", open_only)):
        got = extract_server_duration(frame)
        assert got is not None, label
        assert abs(got - 3.0) < 0.01, label


def test_a_later_record_after_the_tag_does_not_disturb_the_reading() -> None:
    """The tag is not always last; the walk has to keep going past it correctly."""
    frame = (
        tr(0x0667, struct.pack("<d", 1001468.0))
        + tr(0x0420, struct.pack(">I", 0))
        + struct.pack(">HH", 0xFFFF, 0)
    )
    got = extract_server_duration(frame)
    assert got is not None and abs(got - 1.0) < 0.01


def test_call_stats_defaults_to_none() -> None:
    """Existing constructions must not silently acquire a fabricated zero."""
    from saprfclib import CallStats

    stats = CallStats(func_name="X", duration_s=0.1, request_bytes=1, response_bytes=2)
    assert stats.server_duration_s is None
