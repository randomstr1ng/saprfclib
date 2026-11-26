# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Inbound bgRFC frames for server tests, made from the calls ABAP sent (#119).

Each builder starts from a live frame in tests/golden/trfc/bgrfc_inbound.json and
changes only the values a test needs: the unit id and kind, the queue, the calls
in SDATA, or the function name. Everything else stays as ABAP sent it.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from saprfclib.invoke import (
    BGRFC_UNIT_KIND_QRFC_OUTBOUND,
    BGRFC_UNIT_KIND_TRFC_OUTBOUND,
    _iter_tlv_records,
    build_bgrfc_sdata,
    tlv_record,
)

FIXTURE = json.loads((Path(__file__).parent / "golden" / "trfc" / "bgrfc_inbound.json").read_text())
_TERM = bytes.fromhex("ffff0000ffff")
_KIND = {"T": BGRFC_UNIT_KIND_TRFC_OUTBOUND, "Q": BGRFC_UNIT_KIND_QRFC_OUTBOUND}


def live(case: str, key: str) -> bytes:
    return bytes.fromhex(FIXTURE[case][key])


def _records(frame: bytes) -> list[tuple[int, bytes]]:
    assert frame.endswith(_TERM)
    return list(_iter_tlv_records(frame))


def _join(records: list[tuple[int, bytes]]) -> bytes:
    return b"".join(tlv_record(t, v) for t, v in records) + _TERM


def _set_values(frame: bytes, values: dict[str, bytes]) -> bytes:
    records = _records(frame)
    for i in range(len(records) - 1):
        tag, value = records[i]
        if tag == 0x0201 and records[i + 1][0] == 0x0203:
            name = value.decode("utf-16-le")
            if name in values:
                records[i + 1] = (0x0203, values[name])
    return _join(records)


def live_calls(case: str = "reference", key: str = "t_ship") -> list[tuple[str, bytes]]:
    """The (function, record) pairs ABAP put in a captured unit."""
    from saprfclib.invoke import parse_bgrfc_sdata

    return parse_bgrfc_sdata(_values(live(case, key))["SDATA"])


def _values(frame: bytes) -> dict[str, bytes]:
    records = _records(frame)
    return {
        records[i][1].decode("utf-16-le"): records[i + 1][1]
        for i in range(len(records) - 1)
        if records[i][0] == 0x0201 and records[i + 1][0] == 0x0203
    }


def ship_frame(unit_id: str, unit_type: str, calls: list[tuple[str, bytes]]) -> bytes:
    """BGRFC_DEST_SHIP as ABAP sent it, for this unit and these calls."""
    template = live("reference", "q_ship" if unit_type == "Q" else "t_ship")
    sstate = bytearray(_values(template)["SSTATE"])
    sstate[:16] = bytes.fromhex(unit_id)
    sstate[16:20] = struct.pack("<i", _KIND[unit_type])
    sdata = build_bgrfc_sdata(calls) if calls else _empty_sdata()
    return _set_values(template, {"SSTATE": bytes(sstate), "SDATA": sdata})


def _empty_sdata() -> bytes:
    # build_bgrfc_sdata refuses an empty unit; a unit of one call with the call cut
    # out is what a peer sending no calls would put on the wire.
    from saprfclib.compress import sapcompress_compress_lzh, sapcompress_decompress

    full = build_bgrfc_sdata([("X", b"")])
    (n,) = struct.unpack_from("<I", full, 16)
    plain = bytearray(sapcompress_decompress(full[16:], n))
    plain[0x7C:0x80] = b"\0\0\0\0"
    plain = plain[:0x80] + plain[-2:]
    return full[:16] + sapcompress_compress_lzh(bytes(plain))


def unit_frame(function: str, unit_id: str, unit_type: str) -> bytes:
    """A call carrying UNIT_ID and UNIT_KIND (BGRFC_DEST_CONFIRM as ABAP sent it)."""
    frame = _set_values(
        live("reference", "t_confirm"),
        {"UNIT_ID": bytes.fromhex(unit_id), "UNIT_KIND": struct.pack("<i", _KIND[unit_type])},
    )
    records = [(t, function.encode("utf-16-le") if t == 0x0102 else v) for t, v in _records(frame)]
    return _join(records)
