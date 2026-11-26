# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""A parked request is re-sent in a frame of the connection it goes out on (#115).

``retry_parked`` used to send the stored frame as it was. That frame carries the GW
handle and connection index of the connection that built it, and on any later
connection the gateway refused it -- "Conversation NNNN not found" -- whether the
first send had reached the server or not (live probe, ABAP Platform 2025,
2026-11-26, docs/protocol/trfc.md). Framed for the current connection, the same body
ran once when it had never arrived, and was recognised and not run again when it
had.
"""

from __future__ import annotations

import struct

import pytest

from saprfclib.connection import AsyncConnection, Connection, _reframe_parked
from saprfclib.session import SessionState
from saprfclib.stores import InMemoryTidStore

from ._mocks import AsyncMockTransport

BODY = b"\x05\x04\x00\x00\x05\x04" + b"\x01\x02\x00\x03abc\x01\x02" + b"\xff\xff\x00\x00\xff\xff"


class _Session:
    def __init__(self, handle: bytes, conn_idx: int) -> None:
        self.handle = handle
        self.conn_idx = conn_idx


def test_the_body_is_kept_and_the_frame_rebuilt_for_the_current_session() -> None:
    parked = Connection._build_invoke_frame(b"OLDHANDL", BODY, conn_idx=1)
    fresh = _reframe_parked(parked, _Session(b"NEWHANDL", 7))  # type: ignore[arg-type]
    assert fresh == Connection._build_invoke_frame(b"NEWHANDL", BODY, conn_idx=7)
    assert fresh[80:-8] == BODY
    assert fresh[40:48] == b"NEWHANDL"


@pytest.mark.parametrize(
    "parked",
    [
        b"",
        b"\x06" * 40,
        Connection._build_invoke_frame(b"OLDHANDL", BODY, conn_idx=1)[:-1],  # footer cut
        b"\x00" + Connection._build_invoke_frame(b"OLDHANDL", BODY, conn_idx=1)[1:],
    ],
)
def test_bytes_that_are_not_an_invoke_frame_are_refused(parked: bytes) -> None:
    with pytest.raises(ValueError):
        _reframe_parked(parked, _Session(b"NEWHANDL", 7))  # type: ignore[arg-type]


_OK = struct.pack(">HHI", 0x0420, 4, 0) + struct.pack(">HHH", 0xFFFF, 0, 0xFFFF)


async def test_retry_parked_sends_the_body_in_the_current_frame() -> None:
    store = InMemoryTidStore()
    tid = "AAAAAAAAAAAAAAAAAAAAAAAA"
    store.park(tid, Connection._build_invoke_frame(b"OLDHANDL", BODY, conn_idx=1))
    transport = AsyncMockTransport([_OK])
    conn = AsyncConnection(transport, tid_store=store, max_retries=0)
    conn._session._state = SessionState.READY
    conn._session._handle = b"NEWHANDL"
    conn._session._conn_idx = 9

    await conn.retry_parked(tid)

    assert transport.sent == [Connection._build_invoke_frame(b"NEWHANDL", BODY, conn_idx=9)]
    assert store.get_parked(tid) is None
