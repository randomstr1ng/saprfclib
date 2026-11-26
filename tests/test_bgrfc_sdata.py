# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""A bgRFC unit's calls travel in BGRFC_DEST_SHIP's SDATA (#34).

Replays tests/golden/trfc/bgrfc_reference.json: six units the reference client
submitted, differing in one way each, and tests/golden/trfc/bgrfc_saprfclib.json:
the server's side of a unit saprfclib submitted, which committed and ran.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Any

import pytest

from saprfclib.codec import RFCTYPE_CHAR
from saprfclib.compress import sapcompress_compress_lzh, sapcompress_decompress
from saprfclib.connection import Connection, _strip_gw_header
from saprfclib.invoke import (
    _BGRFC_ROW_MID,
    BGRFC_UNIT_KIND_QUEUED,
    BGRFC_UNIT_KIND_TRFC_OUTBOUND,
    TrfcOrigin,
    _iter_tlv_records,
    bgrfc_ship_params,
    build_bgrfc_sdata,
    build_trfc_call,
)
from saprfclib.types import RFC_IMPORT, FieldDesc, FunctionDesc

from ._mocks import MockTransport
from .test_connection import _handshake_responses

GOLDEN = Path(__file__).parent / "golden" / "trfc"
REF = json.loads((GOLDEN / "bgrfc_reference.json").read_text())
OURS = json.loads((GOLDEN / "bgrfc_saprfclib.json").read_text())
PREFIX = bytes.fromhex(REF["sdata_prefix_hex"])


def _rows(plain: bytes) -> list[tuple[str, bytes]]:
    """(function, record) per call, read by the lengths the plaintext declares."""
    count = struct.unpack_from(">I", plain, 0x7C)[0]
    pos, rows = 0x80, []
    for _ in range(count):
        name = plain[pos + 5 : pos + 65].decode("utf-16-le").rstrip()
        pos += 65 + len(_BGRFC_ROW_MID)
        (n,) = struct.unpack_from(">I", plain, pos)
        rows.append((name, plain[pos + 4 : pos + 4 + n]))
        pos += 4 + n + 2
    assert plain[pos:] == b"\xbf\x04"
    return rows


def _plain(sdata: bytes) -> bytes:
    assert sdata[:16] == PREFIX
    (length,) = struct.unpack_from("<I", sdata, 16)
    return sapcompress_decompress(sdata[16:], length)


@pytest.mark.parametrize("case", sorted(REF["units"]))
def test_sdata_reproduces_every_captured_unit(case: str) -> None:
    unit = REF["units"][case]
    plain = bytes.fromhex(unit["plain_hex"])
    rows = _rows(plain)
    assert [name for name, _ in rows] == [c[0] for c in unit["calls"]]
    assert _plain(build_bgrfc_sdata(rows)) == plain


def _origin_of(record: bytes) -> TrfcOrigin:
    tags = dict(_iter_tlv_records(record))

    def text(tag: int) -> str:
        return tags[tag].decode("utf-16-le")

    kernel = text(0x0013)
    return TrfcOrigin(
        tags[0x0514],
        text(0x0007),
        text(0x0011),
        text(0x0012),
        text(0x0008),
        text(0x0130),
        kernel[:4],
        kernel[4:],
        text(0x0006),
    )


_REQUTEXT = FieldDesc("REQUTEXT", RFCTYPE_CHAR, 255, 0, 510, 0, 0, direction=RFC_IMPORT)
_DESCS = {
    "STFC_CONNECTION": FunctionDesc("STFC_CONNECTION", [_REQUTEXT]),
    "RFC_PING": FunctionDesc("RFC_PING", []),
}


@pytest.mark.parametrize("case", ["one", "two", "name", "text2"])
def test_each_record_is_the_call_a_trfc_submit_carries(case: str) -> None:
    unit = REF["units"][case]
    for (_name, record), (func, params) in zip(
        _rows(bytes.fromhex(unit["plain_hex"])), unit["calls"], strict=True
    ):
        built = build_trfc_call(func, _DESCS[func], params, _origin_of(record))
        assert built == record


def test_lzh_blocks_have_the_captured_header_and_read_back() -> None:
    for unit in REF["units"].values():
        plain = bytes.fromhex(unit["plain_hex"])
        block = sapcompress_compress_lzh(plain)
        assert block[:8] == struct.pack("<I", len(plain)) + b"\x12\x1f\x9d\x02"
        assert sapcompress_decompress(block, len(plain)) == plain
        # Within a few bytes of what the reference client's encoder produced.
        assert abs(len(block) - unit["compressed_length"]) <= 16


@pytest.mark.parametrize("data", [b"", b"x", os.urandom(3000), bytes(range(256)) * 40])
def test_lzh_handles_data_deflate_would_store(data: bytes) -> None:
    assert sapcompress_decompress(sapcompress_compress_lzh(data), len(data)) == data


def test_ship_params_carry_the_unit_as_the_reference_client_does() -> None:
    uid = "BC2411CF03C01FE1BAB5A4B131EB6069"
    p = bgrfc_ship_params(
        uid,
        "T",
        [],
        b"sd",
        caller_user="U",
        caller_program="P",
        caller_host="H",
        sending_time="20261126120000",
    )
    assert p["SSTATE"]["UNIT_ID"] == bytes.fromhex(uid)
    assert p["SSTATE"]["UNIT_KIND"] == BGRFC_UNIT_KIND_TRFC_OUTBOUND == 1409196105
    assert p["SSTATE"]["CALLER_CLIENT"] == REF["units"]["one"]["sstate"]["CALLER_CLIENT"]
    assert p["SUPPORTABILITY_INFO"] == {"UNIT_ID": bytes.fromhex(uid), "UNIT_KIND": 1409196105}
    assert p["OUT_IN_QUEUE_NAME_TAB"] == []
    q = bgrfc_ship_params(
        uid,
        "Q",
        ["ZQ"],
        b"sd",
        caller_user="U",
        caller_program="P",
        caller_host="H",
        sending_time="20261126120000",
    )
    # A queued unit: 1409196103 in the capture, not the 1409196101 once assumed.
    assert q["SSTATE"]["UNIT_KIND"] == BGRFC_UNIT_KIND_QUEUED == 1409196103
    assert int(REF["units"]["q"]["sstate"]["UNIT_KIND"]) == 1409196103
    assert q["OUT_IN_QUEUE_NAME_TAB"] == ["ZQ"]


def test_an_empty_unit_or_a_q_unit_without_a_queue_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one call"):
        build_bgrfc_sdata([])
    with pytest.raises(ValueError, match="queue"):
        bgrfc_ship_params(
            "BC2411CF03C01FE1BAB5A4B131EB6069",
            "Q",
            [],
            b"",
            caller_user="",
            caller_program="",
            caller_host="",
            sending_time="20261126120000",
        )


# --------------------------------------------------------------------------- #
# A unit submitted end to end, against the server's recorded side
# --------------------------------------------------------------------------- #


def _sent_params(frame: bytes) -> dict[str, Any]:
    recs = list(_iter_tlv_records(_strip_gw_header(frame)[:-8]))
    return {
        recs[i][1].decode("utf-16-le"): recs[i + 1][1]
        for i in range(len(recs) - 1)
        if recs[i][0] == 0x0201 and recs[i + 1][0] == 0x0203
    }


def test_a_unit_is_submitted_checked_and_confirmed() -> None:
    from saprfclib.stores import UnitState

    replies = [bytes.fromhex(h) for h in OURS["replies_hex"]]
    transport = MockTransport(_handshake_responses() + replies)
    conn = Connection(transport)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")

    with conn.create_unit() as unit:
        unit.call("STFC_CONNECTION", REQUTEXT="our-bg-one")
    assert conn.get_unit_state(unit.unit_id, unit.unit_type) is UnitState.COMMITTED
    conn.confirm_unit(unit.unit_id, unit.unit_type)

    ship = next(f for f in transport.sent if "BGRFC_DEST_SHIP".encode("utf-16-le") in f[80:200])
    params = _sent_params(ship)
    rows = _rows(_plain(params["SDATA"]))
    assert [name for name, _ in rows] == ["STFC_CONNECTION"]
    call = rows[0][1]
    assert call == build_trfc_call(
        "STFC_CONNECTION", _DESCS["STFC_CONNECTION"], {"REQUTEXT": "our-bg-one"}, _origin_of(call)
    )
    assert params["SSTATE"][:16] == bytes.fromhex(unit.unit_id)
    assert params["SSTATE"][16:20] == struct.pack("<i", 1409196105)
