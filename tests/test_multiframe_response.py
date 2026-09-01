# SPDX-License-Identifier: MPL-2.0
"""Responses larger than one gateway frame arrive as several, and must be joined.

Captured live on A4H, kernel 793: RFC_READ_TABLE on DD03L with ROWCOUNT=2000
came back as a 28080-byte frame that stopped 197 bytes short of a 250-byte
0x0305 record, followed by a 25593-byte frame whose body is not a TLV stream at
all -- it begins mid-record. ``Connection.call`` issued one ``recv_message()``
per invoke, so the reply failed to parse and the remainder stayed queued for the
next call to misread.

The interesting part was choosing what drives reassembly. Two header fields
looked like "more follows" markers:

    bytes 17-20 (BE int32)   -1 on part1, 500 on part2
    bytes 60-63 (BE uint32)   0 on part1,   1 on part2

Both are wrong. They are the same signal -- identical across all thirteen frames
compared -- and both also fire on ``signon_incomplete_752_response.bin`` and
``cpic_logon_error_response.bin``, which are complete terminal replies with
nothing following them. A loop trusting either would hang on a failed logon,
waiting for a frame that is never sent. Reassembly is driven by the stream's own
0xFFFF terminator instead, which is confirmed structure rather than an inferred
flag.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from saprfclib.invoke import tlv_stream_status

GOLDEN = Path(__file__).parent / "golden" / "framing"
PART1 = GOLDEN / "multiframe_read_table_part1.bin"
PART2 = GOLDEN / "multiframe_read_table_part2.bin"


def _body(path: Path) -> bytes:
    raw = path.read_bytes()
    return raw[80:] if raw[:1] == b"\x06" else raw


def test_neither_frame_is_a_complete_response_alone() -> None:
    assert tlv_stream_status(_body(PART1)) == "truncated"
    # part2 is raw continuation bytes; walked standalone it derails immediately
    # on a bogus tag rather than looking merely short.
    assert tlv_stream_status(_body(PART2)) == "not_tlv"


def test_the_bodies_concatenate_directly() -> None:
    """No trailer, no preamble, no re-framing -- a literal byte continuation."""
    joined = _body(PART1) + _body(PART2)
    assert len(joined) == 53513
    assert tlv_stream_status(joined) == "complete"


def test_frame_payload_length_is_carried_at_offset_56() -> None:
    """The cross-check that confirms the 80-byte header split is right.

    Exact on both frames here and on every server response among the other
    golden fixtures. The docs previously mapped 52-63 as an RFC library name
    string; these frames show three BE uint32 instead.
    """
    for path in (PART1, PART2):
        raw = path.read_bytes()
        assert struct.unpack_from(">I", raw, 56)[0] == len(raw) - 80


@pytest.mark.parametrize("fixture", ["signon_incomplete_752_response.bin"])
def test_the_header_markers_would_have_hung_the_reader(fixture: str) -> None:
    """Why reassembly is not driven by bytes 17-20 or 60-63.

    This fixture is a complete, self-contained ABAP exception -- it parses to an
    AbapApplicationError carrying 'Logon data incomplete.' -- yet it carries the
    same marker values as the frame that genuinely continues. Had either field
    driven the loop, every failed logon would have blocked on a continuation
    frame the server was never going to send.
    """
    raw = (GOLDEN / fixture).read_bytes()
    assert struct.unpack_from(">i", raw, 17)[0] == -1
    assert struct.unpack_from(">I", raw, 60)[0] == 0
    assert struct.unpack_from(">i", PART1.read_bytes(), 17)[0] == -1
    # ... and yet this one is complete, which is the whole point.
    assert tlv_stream_status(raw[80:]) == "complete"


def test_a_cpic_refusal_is_not_mistaken_for_a_truncated_stream() -> None:
    """Its body is EBCDIC, so record zero claims 50629 bytes in a 97-byte frame.

    Classified not_tlv rather than truncated, so it goes straight to the parser
    that can report it instead of blocking on a continuation that does not exist.
    """
    raw = (GOLDEN / "cpic_logon_error_response.bin").read_bytes()
    assert tlv_stream_status(raw[80:]) == "not_tlv"


def test_reassembly_through_the_connection_read_path() -> None:
    """End to end: the real frames, through the function that joins them."""
    from saprfclib.connection import _join_response_frames

    frames = iter([PART1.read_bytes(), PART2.read_bytes()])
    joined = _join_response_frames(lambda: next(frames), "RFC_READ_TABLE")
    assert len(joined) == 53513
    assert tlv_stream_status(joined) == "complete"
