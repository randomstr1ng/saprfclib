# SPDX-License-Identifier: MPL-2.0
"""The tRFC/bgRFC submit paths must read their reply, not discard it (#15).

Every one of these methods used to send its frame and then call
``recv_message()`` once, throwing the result away. Two failures followed from
that, and neither showed up as an error:

  * **A refusal read as success.** ``BGRFC_DEST_SHIP`` answering with an ABAP
    exception was indistinguishable from it answering RFC_OK, so ``_submit_unit``
    returned normally either way. That is why the bgRFC live test could pass on a
    system where bgRFC was switched off, and why ``invoke.py`` carried a comment
    claiming the encoding had been confirmed by a gate that never checked
    anything.

  * **The connection desynced.** Replies longer than one frame left their
    remainder in the socket. The next call on that connection read those bytes as
    the head of its own reply, which is how an ``RFC_READ_TABLE`` issued after a
    unit submit came back as ``malformed TLV: tag 0x2a45 length 21074`` -- 0x2a45
    being the ASCII ``*E`` of an error string, not a tag at all.

The offline suite passed both before and after the fix, because nothing asserted
on the reply. These tests do, so the discard cannot come back.
"""

from __future__ import annotations

import pathlib

import pytest

from saprfclib.connection import AsyncConnection
from saprfclib.exceptions import AbapApplicationError
from saprfclib.session import SessionState

GOLDEN = pathlib.Path(__file__).parent / "golden" / "framing"

# A real ABAP exception reply (message class FL, number 046, FU_NOT_FOUND).
# Used rather than a hand-built frame so the test fails if our idea of what an
# exception looks like drifts from what a server actually sends.
EXCEPTION_REPLY = (GOLDEN / "gfi_fu_not_found_response.bin").read_bytes()
OK_REPLY = (GOLDEN / "rfcping_response.bin").read_bytes()
# A reply the gateway split across two frames. The submit paths used to read one
# frame, so the second stayed in the socket for the next call to swallow.
MULTIFRAME = [
    (GOLDEN / "multiframe_read_table_part1.bin").read_bytes(),
    (GOLDEN / "multiframe_read_table_part2.bin").read_bytes(),
]

UNIT_ID = "34F62E6D31B24174AD8A92CBD9D02F26"
TID = "ABCDEF1234567890ABCDEF12"


class _ScriptedTransport:
    """Async transport double replaying a fixed list of replies, one per recv."""

    def __init__(self, replies: list[bytes]) -> None:
        self.sent: list[bytes] = []
        self._replies = list(replies)
        self.recv_count = 0

    async def send_message(self, payload: bytes) -> None:
        self.sent.append(bytes(payload))

    async def recv_message(self) -> bytes:
        self.recv_count += 1
        if not self._replies:
            raise EOFError("transport exhausted: more reads than replies scripted")
        return self._replies.pop(0)

    async def close(self) -> None:
        pass

    @property
    def unread(self) -> int:
        return len(self._replies)


def _conn(replies: list[bytes]) -> tuple[AsyncConnection, _ScriptedTransport]:
    transport = _ScriptedTransport(replies)
    conn = AsyncConnection(transport, max_retries=0, retry_delay=0.0)
    conn._session._state = SessionState.READY
    return conn, transport


# --------------------------------------------------------------------------- #
# A refusal must reach the caller
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_submit_unit_raises_when_the_backend_refuses() -> None:
    """An ABAP exception to BGRFC_DEST_SHIP must not be reported as a submit."""
    conn, _ = _conn([EXCEPTION_REPLY])
    with pytest.raises(AbapApplicationError):
        await conn._submit_unit(UNIT_ID, "T", [], [])


@pytest.mark.asyncio
async def test_confirm_unit_raises_when_the_backend_refuses() -> None:
    """confirm_unit() returning cleanly used to prove only that bytes were sent."""
    conn, _ = _conn([EXCEPTION_REPLY])
    with pytest.raises(AbapApplicationError):
        await conn.confirm_unit(UNIT_ID, "T")


@pytest.mark.asyncio
async def test_get_unit_state_raises_rather_than_reporting_not_found() -> None:
    """An error reply must not decode to a plausible-looking UnitState.

    _parse_unit_state_response falls back to NOT_FOUND for anything it cannot
    read, so without the error check an exception reply became "the unit is not
    there" -- a legitimate state, and the one the caller is least likely to
    question.
    """
    conn, _ = _conn([EXCEPTION_REPLY])
    with pytest.raises(AbapApplicationError):
        await conn.get_unit_state(UNIT_ID, "T")


@pytest.mark.asyncio
async def test_call_transactional_raises_when_the_backend_refuses() -> None:
    """The tRFC docstring promises this propagates; it could not while discarded."""
    conn, _ = _conn([EXCEPTION_REPLY])
    with pytest.raises(AbapApplicationError):
        await conn.call_transactional("STFC_CONNECTION", tid=TID)


@pytest.mark.asyncio
async def test_confirm_tid_raises_when_the_backend_refuses() -> None:
    conn, _ = _conn([EXCEPTION_REPLY])
    with pytest.raises(AbapApplicationError):
        await conn.confirm_tid(TID)


# --------------------------------------------------------------------------- #
# The whole reply must be consumed
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_multi_frame_reply_is_consumed_whole() -> None:
    """A submit whose reply spans two frames must read both.

    A single-frame reply cannot detect this: one read consumes it either way. It
    takes a chunked reply to tell "read the reply" apart from "read one frame and
    hope", which is why the earlier version of this test proved nothing.
    """
    conn, transport = _conn([*MULTIFRAME])
    await conn._submit_unit(UNIT_ID, "T", [], [])
    assert transport.recv_count == 2, (
        f"read {transport.recv_count} frame(s) of a two-frame reply; the remainder "
        "stays in the socket and the next call parses it as its own TLV stream"
    )
    assert transport.unread == 0


@pytest.mark.asyncio
async def test_the_call_after_a_multi_frame_submit_is_not_desynced() -> None:
    """The shape of the live failure: a submit, then an ordinary call.

    With the submit under-reading, the second call received frame two of the
    first reply and raised "malformed TLV: tag 0x2a45". Here the scripted
    transport runs dry instead, which is the same fault made visible.
    """
    conn, transport = _conn([*MULTIFRAME, OK_REPLY])
    await conn._submit_unit(UNIT_ID, "T", [], [])
    await conn.confirm_unit(UNIT_ID, "T")
    assert transport.unread == 0
    assert transport.recv_count == 3
