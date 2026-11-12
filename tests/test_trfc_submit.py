# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""tRFC / qRFC submit and confirm, replayed against the reference client (issue #36).

Golden fixture ``tests/golden/trfc/trfc_reference.json`` holds what the reference
client sent to an S/4HANA system for a tRFC LUW of two calls, the same as qRFC, and
a call large enough to span three DATA rows, plus the server's DDIF_FIELDINFO_GET
replies for the two row types. Every request rebuilt here must equal the captured one
byte for byte.
"""

from __future__ import annotations

import struct

import pytest

from saprfclib import invoke
from saprfclib.connection import _join_response_frames, _strip_gw_header
from saprfclib.exceptions import IncompleteDescriptorError
from saprfclib.invoke import (
    TrfcOrigin,
    build_trfc_call,
    build_trfc_confirm_request,
    build_trfc_request,
    raise_for_rfc_error,
)
from saprfclib.types import RFC_IMPORT, FieldDesc, FunctionDesc
from tests import _trfc_fixture as trfc_fixture

FX = trfc_fixture.FX
GW = 80  # GW header + RFC marker in front of the TLV body
FOOTER = 8  # invoke-frame trailer behind it
PIECE = 7 * 255  # ARFCDATA01..07 per DATA row; the row's last byte is padding


def _body(hex_frame: str) -> bytes:
    f = bytes.fromhex(hex_frame)
    return f[GW:-FOOTER]


def _records(data: bytes) -> list[tuple[int, bytes]]:
    out, p = [], 0
    while p + 4 <= len(data):
        tag, n = struct.unpack_from(">HH", data, p)
        if n == 0xFFFF and tag != 0xFFFF:
            n = struct.unpack_from(">I", data, p + 4)[0]
            p += 4
        out.append((tag, data[p + 4 : p + 4 + n]))
        p += 4 + n
        if p + 2 <= len(data) and struct.unpack_from(">H", data, p)[0] == tag:
            p += 2
        if tag == 0xFFFF:
            break
    return out


def _stream_end(data: bytes) -> int:
    """Offset just past the terminator record FF FF 00 00 FF FF of a TLV stream."""
    p = 0
    while True:
        tag, n = struct.unpack_from(">HH", data, p)
        if tag == 0xFFFF:
            return p + 6
        if n == 0xFFFF:
            n = struct.unpack_from(">I", data, p + 4)[0]
            p += 4
        p += 4 + n
        if struct.unpack_from(">H", data, p)[0] == tag:
            p += 2


_type_desc = trfc_fixture.type_desc
SHIP = trfc_fixture.SHIP


def _origin(token: bytes) -> TrfcOrigin:
    return TrfcOrigin(session_token=token, **FX["origin"])


def _submitted(section: str) -> tuple[str, list[tuple[str, bytes]], bytes]:
    """TID, the LUW's (function, serialized call) pairs, and the session token."""
    recs = _records(_body(FX[section]["submit"]["request"]))
    rows = [v for t, v in recs if t == 0x0303]
    state = [r for r in rows if len(r) == 972]
    data = [r for r in rows if len(r) == 1918]
    tid = state[0][:48].decode("utf-16-le")
    calls = []
    for s in state:
        luw = s[112:128]
        blob = b"".join(d[132 : 132 + PIECE] for d in data if d[112:128] == luw)
        func = s[144:204].decode("utf-16-le").rstrip()
        # The serialized call ends with the stream terminator; the rest is padding.
        calls.append((func, blob[: _stream_end(blob)]))
    token = dict(_records(calls[0][1]))[0x0514]
    return tid, calls, token


# --- row layouts from the server's metadata -----------------------------------------


def test_row_widths_include_the_structure_padding() -> None:
    # ARFCRDATA's last field ends at 1917; the server's own width, and the reference
    # client's rows, are 1918 (alignment 2, see _DATATYPE_ALIGNMENT).
    assert _type_desc("ARFCRDATA").uc_size == 1918
    assert _type_desc("ARFCRSTATE").uc_size == 972


# --- submit ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "section,queue",
    [("trfc", None), ("qrfc", "ZSAPRFCLIB_Q1"), ("multiblock", None)],
)
def test_submit_is_byte_identical(section: str, queue: str | None) -> None:
    tid, calls, token = _submitted(section)
    rebuilt = build_trfc_request(tid, calls, SHIP, _origin(token), queue=queue)
    assert rebuilt == _body(FX[section]["submit"]["request"])


def test_multiblock_call_spans_three_numbered_rows() -> None:
    recs = _records(_body(FX["multiblock"]["submit"]["request"]))
    first = [
        v
        for t, v in recs
        if t == 0x0303 and len(v) == 1918 and v[112:128] == "00000001".encode("utf-16-le")
    ]
    assert [int.from_bytes(r[128:132], "big") for r in first] == [1, 2, 3]


def test_serialized_call_is_byte_identical() -> None:
    _, calls, token = _submitted("trfc")
    requtext = FieldDesc(
        name="REQUTEXT",
        rfctype=0,
        nuc_length=255,
        nuc_offset=0,
        uc_length=510,
        uc_offset=0,
        decimals=0,
        direction=RFC_IMPORT,
    )
    desc = FunctionDesc(name="STFC_CONNECTION", parameters=[requtext])
    for i, (func, payload) in enumerate(calls, 1):
        built = build_trfc_call(func, desc, {"REQUTEXT": f"trfc-ref-{i}"}, _origin(token))
        assert built == payload


def test_submit_reply_is_success() -> None:
    for section in ("trfc", "qrfc", "multiblock"):
        frames = iter(bytes.fromhex(h) for h in FX[section]["submit"]["reply"])
        reply = _join_response_frames(frames.__next__, "ARFC_DEST_SHIP")
        raise_for_rfc_error(_strip_gw_header(reply))


def test_qrfc_puts_the_queue_into_arfcreserv() -> None:
    recs = _records(_body(FX["qrfc"]["submit"]["request"]))
    state = [v for t, v in recs if t == 0x0303 and len(v) == 972]
    reserv = state[0][422:932].decode("utf-16-le")
    assert reserv[:44].rstrip() == "python3"
    assert reserv[44:].rstrip() == "IZSAPRFCLIB_Q1"


# --- confirm -----------------------------------------------------------------------


@pytest.mark.parametrize("section", ["trfc", "qrfc"])
def test_confirm_is_byte_identical(section: str) -> None:
    tid, _, _ = _submitted(section)
    assert build_trfc_confirm_request(tid) == _body(FX[section]["confirm"]["request"])


# --- refusals ----------------------------------------------------------------------


def test_queue_longer_than_the_queue_column_is_refused() -> None:
    tid, calls, token = _submitted("trfc")
    build_trfc_request(tid, calls, SHIP, _origin(token), queue="Q" * 24)
    with pytest.raises(ValueError, match="too long"):
        build_trfc_request(tid, calls, SHIP, _origin(token), queue="Q" * 25)


def test_empty_luw_is_refused() -> None:
    tid, _, token = _submitted("trfc")
    with pytest.raises(ValueError, match="at least one call"):
        build_trfc_request(tid, [], SHIP, _origin(token))


def test_bad_tid_is_refused() -> None:
    _, calls, token = _submitted("trfc")
    with pytest.raises(ValueError):
        build_trfc_request("short", calls, SHIP, _origin(token))
    with pytest.raises(ValueError):
        build_trfc_confirm_request("a" * 24)  # lower case is outside the set


def test_metadata_without_state_table_is_refused() -> None:
    tid, calls, token = _submitted("trfc")
    only_data = FunctionDesc(name="ARFC_DEST_SHIP", parameters=[SHIP.parameters[0]])
    with pytest.raises(IncompleteDescriptorError, match="STATE"):
        build_trfc_request(tid, calls, only_data, _origin(token))


def test_max_queue_name_matches_the_documented_limit() -> None:
    assert invoke._MAX_QUEUE_NAME == 24
