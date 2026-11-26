# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""A reply split across frames joins the same wherever it is split (#114).

The other multi-frame tests replay captures split where the server split them. The
joiner's claim is more general: reassembly is driven by the TLV stream's own end, so
the split point must not matter -- the middle of a tag, of a length, of a value or of
the terminator included. Here a captured reply is cut at random offsets and sent
again in synthetic frames.

The frames reuse captured GW headers as they are -- the first frame's, a middle
continuation's and a final one's (bytes 60-63 read 0 and 1, which
``_frame_reports_itself_final`` reads) -- with one change: bytes 56-59 carry the
payload length (test_multiframe_response.py), set to the length of each new piece.
"""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from saprfclib.connection import (
    _MAX_RESPONSE_FRAMES,
    _join_response_frames,
    _join_response_frames_async,
)
from saprfclib.invoke import tlv_stream_status

GOLDEN = Path(__file__).parent / "golden" / "framing"
GW = 80

FIRST = (GOLDEN / "multiframe_read_table_part1.bin").read_bytes()[:GW]
MIDDLE = (GOLDEN / "multiframe_middle_frame.bin").read_bytes()[:GW]
FINAL = (GOLDEN / "multiframe_final_frame.bin").read_bytes()[:GW]


def _body(*names: str) -> bytes:
    return b"".join((GOLDEN / n).read_bytes()[GW:] for n in names)


# Two captured replies: RFC_READ_TABLE in two frames (one compressed 0x0305 stream),
# and a seven-frame RFC_READ_TABLE from another release.
BODIES = {
    "read_table": _body("multiframe_read_table_part1.bin", "multiframe_read_table_part2.bin"),
    "ucon752": _body(*(f"multiframe_rrt_ucon752_{i:02d}.bin" for i in range(7))),
}


def test_the_captured_bodies_are_complete_streams() -> None:
    for body in BODIES.values():
        assert tlv_stream_status(body) == "complete"


def _frame(header: bytes, piece: bytes) -> bytes:
    head = bytearray(header)
    struct.pack_into(">I", head, 56, len(piece))
    return bytes(head) + piece


def _frames(body: bytes, cuts: list[int], *, last_final: bool = True) -> list[bytes]:
    edges = [0, *cuts, len(body)]
    pieces = [body[a:b] for a, b in zip(edges, edges[1:], strict=False)]
    frames = []
    for i, piece in enumerate(pieces):
        if i == 0:
            header = FIRST if len(pieces) > 1 or not last_final else FINAL
        elif i == len(pieces) - 1 and last_final:
            header = FINAL
        else:
            header = MIDDLE
        frames.append(_frame(header, piece))
    return frames


def _reader(frames: list[bytes]):  # type: ignore[no-untyped-def]
    queue = list(frames)

    def read() -> bytes:
        if not queue:
            raise EOFError("no more frames")
        return queue.pop(0)

    return read, queue


# The first frame must hold the first record's 4-byte tag and length. A buffer in
# which not even one record parses is "not TLV" by design (tlv_stream_status): that
# is how a CPIC refusal, an EBCDIC body, is told apart from a truncated reply, so a
# first frame of fewer than 4 bytes is not read on from. No real reply comes close:
# every captured one opens with an empty 0x0500 record (4 bytes plus its closing
# tag), and a gateway frame carries up to 28000 bytes.
_FIRST_RECORD_HEADER = 4


def _draw_cuts(data: st.DataObject, body: bytes, max_frames: int = 12) -> list[int]:
    assert body[:2] == b"\x05\x00"
    n = data.draw(st.integers(0, max_frames - 1), label="cuts")
    cuts = data.draw(
        st.lists(
            st.integers(_FIRST_RECORD_HEADER, len(body) - 1), min_size=n, max_size=n, unique=True
        ),
        label="offsets",
    )
    return sorted(cuts)


@settings(max_examples=150, deadline=None)
@given(name=st.sampled_from(sorted(BODIES)), data=st.data())
def test_any_split_joins_to_the_same_bytes(name: str, data: st.DataObject) -> None:
    body = BODIES[name]
    cuts = _draw_cuts(data, body)
    frames = _frames(body, cuts)

    read, left = _reader(frames)
    assert _join_response_frames(read, "F") == body
    assert left == [], "every frame is read, and no more"

    async def main() -> bytes:
        queue = list(frames)

        async def aread() -> bytes:
            return queue.pop(0)

        joined = await _join_response_frames_async(aread, "F")
        assert queue == []
        return joined

    assert asyncio.run(main()) == body


@settings(max_examples=100, deadline=None)
@given(name=st.sampled_from(sorted(BODIES)), data=st.data())
def test_a_reply_cut_short_is_reported_not_waited_for(name: str, data: st.DataObject) -> None:
    """The last frame is lost, and the one before it says it is the last."""
    body = BODIES[name]
    cuts = _draw_cuts(data, body)
    if not cuts:
        cuts = [len(body) // 2]
    frames = _frames(body, cuts)[:-1]
    # The frame now ending the reply carries the final header.
    frames[-1] = _frame(FINAL, frames[-1][GW:])
    read, _ = _reader(frames)
    with pytest.raises(ValueError, match="reports itself as the last"):
        _join_response_frames(read, "F")


def test_a_reply_split_into_more_frames_than_the_cap_is_refused() -> None:
    body = BODIES["read_table"]
    step = len(body) // (_MAX_RESPONSE_FRAMES + 5)
    cuts = list(range(step, len(body) - 1, step))
    read, _ = _reader(_frames(body, cuts))
    with pytest.raises(ValueError, match="refusing to read further"):
        _join_response_frames(read, "F")
