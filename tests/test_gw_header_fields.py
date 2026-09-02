# SPDX-License-Identifier: MPL-2.0
"""GW header fields, established by comparing the whole capture corpus.

Several entries in the 76-byte header table were guesses that a single capture
could not disprove, and one was simply wrong. What settles them is not a better
frame but *more* frames: a field that looks like a flags word in one reply is
obviously a counter once you have twenty-two of them in sequence.

These pin the fields that comparison established, so a future edit to the table
has to disagree with the captures rather than with a comment.
"""

from __future__ import annotations

import glob
import struct
from pathlib import Path

GOLDEN = Path(__file__).parent / "golden"


def _gw_frames() -> list[tuple[str, bytes]]:
    out = []
    for p in sorted(glob.glob(str(GOLDEN / "**" / "*.bin"), recursive=True)):
        raw = Path(p).read_bytes()
        if raw[:1] == b"\x06" and len(raw) >= 80:
            out.append((Path(p).name, raw))
    return out


def _is_request(raw: bytes) -> bool:
    return struct.unpack_from(">I", raw, 56)[0] == 0


def test_the_reserved_bytes_are_zero_everywhere() -> None:
    """Recorded as unknown; they are simply never used in anything captured.

    "Unknown" and "always zero across every frame we have" are different claims,
    and the second is the one the corpus supports.
    """
    for name, raw in _gw_frames():
        for off, ln in ((8, 2), (11, 2), (14, 2), (22, 2), (28, 2), (32, 2)):
            assert raw[off : off + ln] == b"\x00" * ln, f"{name} byte {off}"


def test_byte_16_separates_responses_from_requests() -> None:
    for name, raw in _gw_frames():
        assert raw[16] == (0 if _is_request(raw) else 1), name


def test_byte_13_is_a_frame_sequence_number() -> None:
    """1-based within a response, 0 on requests.

    The table had bytes 11-15 as five unknown bytes of "zeros / CPIC internal".
    Four of them are zero; the middle one counts. A 22-frame reply numbered its
    frames 1..22 with no exceptions, which is not something a flags byte does.
    """
    parts = [
        (GOLDEN / "framing" / "multiframe_read_table_part1.bin").read_bytes(),
        (GOLDEN / "framing" / "multiframe_read_table_part2.bin").read_bytes(),
    ]
    assert [p[13] for p in parts] == [1, 2]

    for name, raw in _gw_frames():
        if _is_request(raw):
            assert raw[13] == 0, name


def test_bytes_30_31_are_a_position_marker() -> None:
    """One BE uint16, not two unknown bytes.

    0x0108 does not complete the response, 0x0100 is a middle frame, 0x050C
    completes it. The marker agrees with the independent flag at byte 60 on every
    frame, which is what makes it a reading rather than a coincidence.
    """
    NOT_FINAL, MIDDLE, FINAL = 0x0108, 0x0100, 0x050C
    for name, raw in _gw_frames():
        marker = struct.unpack_from(">H", raw, 30)[0]
        assert marker in (NOT_FINAL, MIDDLE, FINAL), f"{name}: 0x{marker:04x}"
        if not _is_request(raw):
            completes = struct.unpack_from(">I", raw, 60)[0] == 1
            assert completes == (marker == FINAL), name


def test_bytes_52_to_63_are_three_integers_not_a_library_name() -> None:
    """The table called 52-63 an "RFC library name + version, null-padded".

    Twelve bytes are readable as a padded string, which is why that survived. It
    is three BE uint32: a constant, this frame's payload length, and the
    completion flag.
    """
    for name, raw in _gw_frames():
        constant, length, _flag = (struct.unpack_from(">I", raw, o)[0] for o in (52, 56, 60))
        if _is_request(raw):
            assert (constant, length) == (0, 0), name
        else:
            assert constant == 2, name
            assert length == len(raw) - 80, f"{name}: {length} != {len(raw) - 80}"


def test_0x0503_marks_success_and_is_complementary_to_0x0417() -> None:
    """Recorded as "response flag 2, meaning unknown".

    The meaning comes out of the corpus rather than any single frame: across every
    RFC-layer reply, 0x0503 is present exactly when the exception marker is not.
    """

    def tagset(raw: bytes) -> set[int]:
        body, out, pos = raw[80:], set(), 0
        n = len(body)
        while pos + 4 <= n:
            tag, ln = struct.unpack_from(">HH", body, pos)
            pos += 4
            if tag == 0xFFFF:
                break
            if ln == 0xFFFF:
                if pos + 4 > n:
                    break
                ln = struct.unpack_from(">I", body, pos)[0]
                pos += 4
            if pos + ln > n:
                break
            out.add(tag)
            pos += ln
            if pos + 2 <= n and struct.unpack_from(">H", body, pos)[0] == tag:
                pos += 2
        return out

    checked = 0
    for name, raw in _gw_frames():
        if _is_request(raw):
            continue
        tags = tagset(raw)
        if 0x0500 not in tags:
            continue
        checked += 1
        assert (0x0503 in tags) != (0x0417 in tags), name
    assert checked >= 8, "corpus shrank; this assertion is no longer meaningful"
