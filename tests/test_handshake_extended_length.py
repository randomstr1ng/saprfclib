# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The logon TLV parser reads the extended length form (OQ-C08, #113).

Live capture, ABAP Platform 2025, 2026-11-26: the reference client, given a
70000-character logon ticket, wrote it as one record
``06 70 FF FF 00 01 11 70`` + 70000 bytes + ``06 70`` -- tag 0x0670, 0xFFFF in the
length field, the length as a 4-byte BE integer -- and the server read the frame and
answered with an ordinary logon refusal (RFC_LOGON_FAILURE). The frame itself is not
stored: it carries the client's addresses and host, and nothing in it but the record
header is needed here.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib.invoke import tlv_record
from saprfclib.session import Session

CAPTURED_HEADER = bytes.fromhex("0670ffff00011170")


def test_the_captured_record_header_is_the_extended_form() -> None:
    record = tlv_record(0x0670, b"A" * 70000)
    assert record[:8] == CAPTURED_HEADER
    assert record[-2:] == b"\x06\x70"


def test_a_long_logon_record_is_read_whole() -> None:
    stream = (
        tlv_record(0x0514, b"\x01" * 16)
        + tlv_record(0x0670, b"A" * 70000)
        + tlv_record(0x0006, "host".encode("utf-16-le"))
        + struct.pack(">HHH", 0xFFFF, 0, 0xFFFF)
    )
    tags = Session._parse_tlv(stream)
    assert tags[0x0670] == b"A" * 70000
    assert tags[0x0006] == "host".encode("utf-16-le")


def test_a_truncated_extended_length_is_refused() -> None:
    with pytest.raises(ValueError, match="extended length truncated"):
        Session._parse_tlv(b"\x06\x70\xff\xff\x00\x01")
    with pytest.raises(ValueError, match="exceeds"):
        Session._parse_tlv(CAPTURED_HEADER + b"A" * 10)


@given(st.lists(st.tuples(st.integers(1, 0xFFFE), st.binary(max_size=300)), max_size=5))
def test_records_written_by_tlv_record_read_back(records: list[tuple[int, bytes]]) -> None:
    stream = b"".join(tlv_record(t, v) for t, v in records) + struct.pack(">HHH", 0xFFFF, 0, 0xFFFF)
    expected: dict[int, bytes] = {}
    for t, v in records:
        expected[t] = v
    assert Session._parse_tlv(stream) == expected
