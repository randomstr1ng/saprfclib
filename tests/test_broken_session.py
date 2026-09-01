# SPDX-License-Identifier: MPL-2.0
"""A call that cannot read its reply must retire the connection.

The failure these cover is not the one that raises. It is the one after it.

When a request has gone out and the reply cannot be consumed to its end -- a
short read, a malformed frame, a response spanning more frames than were read --
the socket is left holding an unknown number of unread bytes. The call that hit
the problem raises, so the caller sees it. The *next* call on that connection
does not: it sends its own request, reads the previous reply's leftovers, and
returns a result belonging to different arguments. Nothing in the data says the
two were swapped.

This was live on A4H before the fix. RFC_READ_TABLE on DD03L with ROWCOUNT=2000
died with "tag 0x0305 length 250 exceeds remaining payload (197 bytes)" -- 0x0305
is a valid compressed-table record and 250 is the size those chunks use, so the
parser was still in sync and the data simply stopped. The session went back to
READY with the remainder still queued.

There is nothing to resynchronise to. No record boundary in the frame format lets
a reader scan forward and re-establish position, so once it is lost it stays lost
and the only safe state is terminal.
"""

from __future__ import annotations

import struct

import pytest

from saprfclib.exceptions import AbapSystemFailure, CommunicationError
from saprfclib.invoke import tlv_record as tr
from saprfclib.session import Session, SessionState

from .test_connection import (  # type: ignore[attr-defined]
    _invoke_response_for_stfc,
    _ready_connection_with_invoke,
)


def _truncated_response() -> bytes:
    """A frame that parses in sync and then runs out, as the live one did.

    0x0305 announces 250 bytes of compressed table content and only 40 follow.
    That is the shape of a reply continued in a frame nobody read -- not of
    corruption, which would derail the walk at the tag instead of the length.
    """
    return tr(0x0500, b"") + struct.pack(">HH", 0x0305, 250) + b"\x00" * 40


def test_truncated_reply_retires_the_connection() -> None:
    conn, _ = _ready_connection_with_invoke([_truncated_response()])
    with pytest.raises(ValueError, match="0x0305") as excinfo:
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert "exceeds remaining payload" in str(excinfo.value)
    assert conn._session.state is SessionState.BROKEN


def test_the_next_call_is_refused_rather_than_answered_with_stale_bytes() -> None:
    """The point of the whole exercise.

    The second response here is a perfectly good STFC_CONNECTION reply. Before
    the fix the second call consumed it and returned ECHOTEXT='hi' -- a plausible
    answer, assembled from a frame that belonged to a call which had already
    failed. The assertion is that this cannot happen: the connection refuses, and
    the refusal names the original fault instead of the confusion downstream.
    """
    conn, _ = _ready_connection_with_invoke(
        [_truncated_response(), _invoke_response_for_stfc(echo="hi")]
    )
    with pytest.raises(ValueError, match="0x0305"):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")

    with pytest.raises(ValueError) as excinfo:
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    message = str(excinfo.value)
    assert "unusable" in message
    assert "0x0305" in message, "the refusal must carry the original cause forward"


def test_ping_is_refused_on_a_retired_connection() -> None:
    """Including the health check, which is how a pool would find out."""
    conn, _ = _ready_connection_with_invoke([_truncated_response()])
    with pytest.raises(ValueError, match="0x0305"):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    with pytest.raises(ValueError, match="unusable"):
        conn.ping()


def test_close_still_works_when_retired() -> None:
    """Retiring must not strand the socket: cleanup has to stay available."""
    conn, _ = _ready_connection_with_invoke([_truncated_response()])
    with pytest.raises(ValueError, match="0x0305"):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    conn.close()
    assert conn._session.state is SessionState.CLOSED


def test_abap_system_failure_does_not_retire() -> None:
    """A parsed error is an outcome, not a framing fault.

    Retiring here would mean a pooled application discarding and reopening a
    connection on every ABAP short dump -- turning ordinary business errors into
    a reconnect storm.
    """
    failure = (
        tr(0x0500, b"")
        + tr(0x0420, struct.pack(">I", 3))
        + struct.pack(">HH", 0xFFFF, 0)
        + b"\xff\xff"
    )
    conn, _ = _ready_connection_with_invoke([failure, _invoke_response_for_stfc(echo="ok")])
    with pytest.raises(AbapSystemFailure):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert conn._session.state is SessionState.READY
    # And the connection genuinely still works, not merely reports that it does.
    assert conn.call("STFC_CONNECTION", REQUTEXT="ok")["ECHOTEXT"].strip() == "ok"


def test_eof_mid_reply_retires_and_reports_as_communication_error() -> None:
    conn, _ = _ready_connection_with_invoke([])
    with pytest.raises(CommunicationError):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert conn._session.state is SessionState.BROKEN


def test_broken_is_terminal() -> None:
    """No path back to READY: mark_ready refuses, it does not quietly revive."""
    session = Session()
    session.mark_broken("test")
    assert session.state is SessionState.BROKEN
    with pytest.raises(ValueError, match="unusable"):
        session.mark_ready()
    assert session.state is SessionState.BROKEN


def test_pool_discards_a_retired_connection_without_pinging_it() -> None:
    """The pool must not lend one on, and must not probe a dead stream to find out."""
    from saprfclib.pool import _is_retired

    class FakeConn:
        def __init__(self, state: SessionState) -> None:
            self._session = Session()
            self._session._state = state
            self.pinged = False

        def ping(self) -> bool:
            self.pinged = True
            return True

    broken = FakeConn(SessionState.BROKEN)
    assert _is_retired(broken) is True

    healthy = FakeConn(SessionState.READY)
    assert _is_retired(healthy) is False

    pool = object.__new__(__import__("saprfclib.pool", fromlist=["ConnectionPool"]).ConnectionPool)
    assert pool._ping_ok(broken) is False
    assert broken.pinged is False, "a known-dead stream must not be written to"
    assert pool._ping_ok(healthy) is True
    assert healthy.pinged is True


def test_is_retired_tolerates_a_connection_without_a_session() -> None:
    """Pool doubles in the wild are duck-typed; the guard must not assume ours."""
    from saprfclib.pool import _is_retired

    assert _is_retired(object()) is False
