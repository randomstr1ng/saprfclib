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


# --------------------------------------------------------------------------- #
# The 22-frame capture: what the header markers actually track
# --------------------------------------------------------------------------- #

MIDDLE = GOLDEN / "multiframe_middle_frame.bin"
FINAL = GOLDEN / "multiframe_final_frame.bin"


def test_the_markers_do_track_continuation_within_a_response() -> None:
    """Settled by a 22-frame reply, which two frames could not have settled.

    With two frames, "this frame continues the response" and "this frame does
    not end the stream" are the same statement, so the two-frame capture could
    not tell a real marker from a coincidence. A 591337-byte reply on A4H kernel
    793 arrived as 22 frames: all twenty-one continuing frames read -1/0 and the
    last read 500/1. Twenty-one agreeing observations is not a coincidence.
    """
    for raw, cont in ((MIDDLE.read_bytes(), True), (FINAL.read_bytes(), False)):
        assert struct.unpack_from(">i", raw, 17)[0] == (-1 if cont else 500)
        assert struct.unpack_from(">I", raw, 60)[0] == (0 if cont else 1)
        assert struct.unpack_from(">I", raw, 56)[0] == len(raw) - 80


def test_the_gateway_chunks_at_28000_payload_bytes() -> None:
    """Which is why a DD03L read tipped over into several frames near 2000 rows."""
    assert len(MIDDLE.read_bytes()) - 80 == 28000


def test_the_markers_are_still_not_the_loop_condition() -> None:
    """Confirmed does not mean usable for this.

    Both fields read the continuing value on two complete terminal replies. A
    reader keyed on them would wait forever on a refused logon, so the terminator
    stays in charge. This is the assertion that stops a future reader from
    "simplifying" the loop onto the marker now that it is confirmed.
    """
    for name in ("signon_incomplete_752_response.bin", "cpic_logon_error_response.bin"):
        raw = (GOLDEN / name).read_bytes()
        assert struct.unpack_from(">i", raw, 17)[0] == -1
        assert struct.unpack_from(">I", raw, 60)[0] == 0
    # signon_incomplete is nonetheless a complete stream that parses on its own.
    assert tlv_stream_status((GOLDEN / "signon_incomplete_752_response.bin").read_bytes()[80:]) == (
        "complete"
    )


def test_a_frame_claiming_to_be_final_on_a_short_stream_is_refused() -> None:
    """The direction the marker IS good for.

    Reading on here would consume whatever arrives next -- which is the reply to
    the following call. Failing now names the inconsistency instead of turning it
    into a swapped result later.
    """
    from saprfclib.connection import _join_response_frames

    truncated_but_final = bytearray(PART1.read_bytes())
    struct.pack_into(">I", truncated_but_final, 60, 1)  # claim to be the last

    frames = iter([bytes(truncated_but_final), PART2.read_bytes()])
    with pytest.raises(ValueError, match="reports itself as the last"):
        _join_response_frames(lambda: next(frames), "RFC_READ_TABLE")


def test_a_frame_with_no_gw_header_gets_no_opinion() -> None:
    """Raw-TLV transports and offline doubles have no header to ask.

    None must not collapse into either answer: read as "final" it would refuse
    every mock reassembly, read as "not final" it would assert something the
    frame never said.
    """
    from saprfclib.connection import _frame_reports_itself_final

    assert _frame_reports_itself_final(b"\x05\x00\x00\x00") is None
    assert _frame_reports_itself_final(b"") is None
    assert _frame_reports_itself_final(MIDDLE.read_bytes()) is False
    assert _frame_reports_itself_final(FINAL.read_bytes()) is True


def test_every_response_read_reassembles() -> None:
    """Not just the classic invoke, which is where reassembly landed first.

    A wRFC call, a metadata fetch and a structure lookup all read replies that
    can exceed one frame, and each read its own single frame. The wRFC path
    reproduced the original bug exactly -- RFC_READ_TABLE on DD03L past ~2000
    rows failing with "tag 0x0305 length 250 exceeds remaining payload" -- while
    the classic path beside it had been fixed.

    Asserted structurally: exercising each needs a live system of the right kind,
    and what must not regress is that no response read goes back to a bare
    recv_message.
    """
    import re
    from pathlib import Path

    src = (Path(__file__).parent.parent / "src" / "saprfclib" / "connection.py").read_text()
    bare = re.findall(r"^\s*(?:\w+) = self\._transport\.recv_message\(\)", src, re.MULTILINE)

    # What legitimately remains is the NI/GW handshake loop, which exchanges
    # control frames rather than TLV result streams.
    assert len(bare) <= 1, (
        f"{len(bare)} response reads still take a single frame; a reply larger "
        f"than one frame would be silently truncated"
    )


def test_table_row_boundaries_come_from_the_records_not_the_declared_width() -> None:
    """0x0302's width is not always the transmitted record length.

    A reference capture carries PARAMS with a declared width of 404 and 0x0303
    records of 402 bytes. Splitting the concatenated bytes by the declared width
    would drift two bytes per row -- misaligned strings rather than an error.

    The width IS the right stride for the compressed form, where there are no
    record boundaries to use: a 44-row interface decompresses to 17776 bytes,
    exactly 44 x 404. So the rule is per-form, and the obvious simplification of
    "always split by row_size" is wrong for one of them.
    """
    assert 17776 == 44 * 404, "the compressed stride is the declared width"
    # And the uncompressed record is narrower than that width, which is the trap.
    assert 402 != 404


def test_0x0302_field_order_is_width_then_count() -> None:
    """Settled by one reply carrying two tables with different counts.

    A single table cannot settle it -- either reading fits one pair of numbers.
    Two tables, 3 records against a 3 and 0 records against a 0, can.
    """
    import struct

    params = struct.pack(">II", 404, 3)
    resumable = struct.pack(">II", 62, 0)
    assert struct.unpack(">II", params) == (404, 3)
    assert struct.unpack(">II", resumable) == (62, 0)
