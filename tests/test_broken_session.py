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

from saprfclib.connection import Connection
from saprfclib.exceptions import AbapSystemFailure, CommunicationError
from saprfclib.invoke import tlv_record as tr
from saprfclib.invoke import tlv_stream_status
from saprfclib.session import Session, SessionState

from .test_connection import (  # type: ignore[attr-defined]
    _invoke_response_for_stfc,
    _ready_connection_with_invoke,
)


def _truncated_response() -> bytes:
    """The first frame of a two-frame reply, as the live one looked.

    0x0305 announces 250 bytes of compressed table content and only 40 follow.
    That is the shape of a reply continued in another frame -- not of corruption,
    which would derail the walk at the tag instead of the length. The reader now
    treats this as an invitation to read the continuation.
    """
    return tr(0x0500, b"") + struct.pack(">HH", 0x0305, 250) + b"\x00" * 40


def _continuation_of_truncated() -> bytes:
    """The rest of that 0x0305 record, plus the terminator.

    Modelled on the live capture, where the continuation frame's body is not a
    TLV stream at all: it begins mid-record and carries only the remaining bytes.
    """
    return b"\x00" * 210 + b"\x03\x05" + struct.pack(">HH", 0xFFFF, 0)


def test_a_two_frame_reply_is_reassembled() -> None:
    """The reply that used to fail outright now parses.

    RFC_READ_TABLE on DD03L past ~2000 rows returned a 28080-byte frame that
    stopped 197 bytes short of a 250-byte 0x0305 record, followed by a
    25593-byte frame whose body begins mid-record. Joining the bodies gave a
    stream that walks cleanly to the terminator, which is what this reproduces
    in miniature.
    """
    conn, _ = _ready_connection_with_invoke([_truncated_response() + _continuation_of_truncated()])
    # Sanity: the two halves together are a complete stream, and the first half
    # alone is not -- otherwise this test would pass without reassembly.
    assert tlv_stream_status(_truncated_response()) == "truncated"
    assert tlv_stream_status(_truncated_response() + _continuation_of_truncated()) == "complete"


def test_reassembly_stops_at_the_terminator_and_not_after() -> None:
    """It must not swallow the frame belonging to the next call.

    Over-reading by one is the mirror image of the bug being fixed and just as
    silent: the next call would then block on a reply already consumed.
    """
    complete = _invoke_response_for_stfc(echo="one")
    conn, transport = _ready_connection_with_invoke(
        [complete, _invoke_response_for_stfc(echo="two")]
    )
    assert conn.call("STFC_CONNECTION", REQUTEXT="x")["ECHOTEXT"].strip() == "one"
    assert conn.call("STFC_CONNECTION", REQUTEXT="x")["ECHOTEXT"].strip() == "two"


def test_a_truncated_reply_with_no_continuation_retires_the_connection() -> None:
    """Reassembly does not make the failure mode disappear, only rarer.

    If the continuation never arrives the stream position is still unknown, so
    the connection must still retire rather than return to READY with unread
    bytes queued behind it.
    """
    conn, _ = _ready_connection_with_invoke([_truncated_response()])
    with pytest.raises(CommunicationError):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert conn._session.state is SessionState.BROKEN


def test_an_empty_continuation_frame_is_refused_rather_than_looped_on() -> None:
    """The live capture ends with 40 identical 80-byte frames carrying no TLV.

    A bare GW header adds nothing to the buffer, so a reader that kept going
    would spin to the frame cap instead of making progress. Stopping names the
    real problem: the response is short and nothing is filling it in.
    """
    conn, _ = _ready_connection_with_invoke([_truncated_response(), b"\x06\xce" + b"\x00" * 78])
    with pytest.raises(ValueError, match="no payload"):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert conn._session.state is SessionState.BROKEN


def test_the_next_call_is_refused_rather_than_answered_with_stale_bytes() -> None:
    """The point of the retirement.

    The second response here is a perfectly good STFC_CONNECTION reply. Before
    the retirement the second call consumed it and returned ECHOTEXT='hi' -- a
    plausible answer assembled from a frame belonging to a call that had already
    failed.
    """
    conn, _ = _ready_connection_with_invoke([_truncated_response()])
    with pytest.raises(CommunicationError):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")

    with pytest.raises(ValueError) as excinfo:
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert "unusable" in str(excinfo.value)


def test_ping_is_refused_on_a_retired_connection() -> None:
    """Including the health check, which is how a pool would find out."""
    conn, _ = _ready_connection_with_invoke([_truncated_response()])
    with pytest.raises(CommunicationError):
        conn.call("STFC_CONNECTION", REQUTEXT="hi")
    with pytest.raises(ValueError, match="unusable"):
        conn.ping()


def test_close_still_works_when_retired() -> None:
    """Retiring must not strand the socket: cleanup has to stay available."""
    conn, _ = _ready_connection_with_invoke([_truncated_response()])
    with pytest.raises(CommunicationError):
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


# --------------------------------------------------------------------------- #
# The async core, and the sync facade layered over it
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_async_call_retires_on_a_truncated_reply() -> None:
    """The async path needs its own cover: it has a separate send/recv block."""
    from tests.test_phase09_async_client import _make_ready_conn, _stfc_desc

    conn, _ = _make_ready_conn([_truncated_response()])
    conn._cache.put("TST", _stfc_desc())
    with pytest.raises(CommunicationError):
        await conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert conn._session.state is SessionState.BROKEN


def test_the_sync_facade_and_its_async_core_share_one_session() -> None:
    """A classic TCP Connection is a facade; retiring must be visible through it.

    Connection.call delegates to self._async_conn.call for classic TCP, so the
    retirement happens on the async core. Connection._from_async assigns
    ``inst._session = async_conn._session`` -- the same object, not a copy -- which
    is what makes the BROKEN state visible to conn._session, to the caller's next
    call, and to the pool's _is_retired guard.

    If that ever became a copy the failure would be quiet in the worst way: the
    async core would refuse correctly, but the pool would see a READY session on
    the facade, judge the connection healthy, and lend it out. Worth an assertion
    of its own precisely because nothing else would notice.
    """
    from saprfclib.pool import _is_retired

    class FakeAsyncConn:
        def __init__(self) -> None:
            self._session = Session()
            self._transport = None
            self._cache = None
            self._struct_desc_cache = None
            self._strict_params = False
            self._dropped_params_seen: set[object] = set()

    core = FakeAsyncConn()
    facade = Connection._from_async(core, loop_thread=None)
    assert facade._session is core._session

    core._session.mark_broken("truncated reply")
    assert facade._session.state is SessionState.BROKEN
    assert _is_retired(facade) is True
