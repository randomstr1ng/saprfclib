# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tables the caller sends and the server edits, replayed from table_delta.json.

The server answers with the edits (append, insert, change, delete) rather than the
table, or with the whole table after a sort or a clear, or with nothing for a table it
did not touch. Every case must come out as the reference client returned it.
"""

from __future__ import annotations

import json
import pathlib
import struct

import pytest

from saprfclib.connection import _join_response_frames, _strip_gw_header
from saprfclib.invoke import (
    _apply_table_deltas,
    build_invoke_request,
    dm_table_ids,
    parse_invoke_response,
    tlv_record,
)
from saprfclib.types import RFC_IMPORT, RFC_TABLES, FieldDesc, FunctionDesc, TypeDesc

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "serialization" / "table_delta.json").read_text(
        encoding="utf-8"
    )
)


def _row_type() -> TypeDesc:
    text = FieldDesc(
        name="TEXT", rfctype=0, nuc_length=72, nuc_offset=0, uc_length=144, uc_offset=0, decimals=0
    )
    return TypeDesc(name="RFC_DB_OPT", fields=[text], nuc_size=72, uc_size=144)


def _table(name: str) -> FieldDesc:
    return FieldDesc(
        name=name,
        rfctype=5,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        type_desc=_row_type(),
        direction=RFC_TABLES,
    )


DESC = FunctionDesc(
    name="Z_SAPRFCLIB_TABDELTA2",
    parameters=[
        _table("ET_OUT"),
        FieldDesc(
            name="IV_OP",
            rfctype=0,
            nuc_length=10,
            nuc_offset=0,
            uc_length=20,
            uc_offset=0,
            decimals=0,
            direction=RFC_IMPORT,
        ),
        _table("IT_KEEP"),
        _table("IT_ROWS"),
    ],
)


def _params(case: dict) -> dict:
    p = {"IV_OP": case["op"]}
    for name, texts in case["sent"].items():
        p[name] = [{"TEXT": t} for t in texts]
    return p


def _reply(case: dict) -> bytes:
    frames = iter(bytes.fromhex(h) for h in case["reply"])
    return _strip_gw_header(_join_response_frames(frames.__next__, "Z_SAPRFCLIB_TABDELTA2"))


@pytest.mark.parametrize("case", FX["cases"], ids=lambda c: c["op"])
def test_result_matches_the_reference_client(case: dict) -> None:
    params = _params(case)
    result = parse_invoke_response(_reply(case), DESC, dm_table_ids(DESC, params), params)
    got = {k: [row["TEXT"] for row in v] for k, v in result.items()}
    assert got == case["result"]


@pytest.mark.parametrize("case", FX["cases"], ids=lambda c: c["op"])
def test_request_tables_match_the_reference_client(case: dict) -> None:
    # Which tables are sent, in which order, under which DM ids: the delta refers to them.
    def tables(tlv: bytes) -> list[tuple[int, bytes]]:
        out, p = [], 0
        while p + 4 <= len(tlv):
            tag, n = struct.unpack_from(">HH", tlv, p)
            if tag == 0xFFFF:
                break
            if tag in (0x0301, 0x0330, 0x0302, 0x0303):
                out.append((tag, tlv[p + 4 : p + 4 + n]))
            p += 4 + n
            if struct.unpack_from(">H", tlv, p)[0] == tag:
                p += 2
        return out

    ref = tables(bytes.fromhex(case["request"])[80:])
    ours = tables(build_invoke_request(DESC.name, DESC, _params(case)))
    assert ours == ref


def _delta(*records: tuple[int, bytes]) -> bytes:
    return b"".join(tlv_record(t, v) for t, v in records) + tlv_record(0xFFFF)


def _row(text: str) -> bytes:
    return text.ljust(72).encode("utf-16-le")


def test_an_unknown_edit_is_refused() -> None:
    params = {"IT_ROWS": [{"TEXT": "A"}]}
    resp = _delta(
        (0x0331, struct.pack(">I", 1)),
        (0x0333, struct.pack(">III", 9, 1, 1)),
        (0x0334, _row("X")),
    )
    with pytest.raises(ValueError, match="not understood"):
        _apply_table_deltas(resp, DESC, {1: "IT_ROWS"}, params)


def test_a_delete_past_the_end_is_refused() -> None:
    params = {"IT_ROWS": [{"TEXT": "A"}]}
    resp = _delta((0x0331, struct.pack(">I", 1)), (0x0332, struct.pack(">III", 5, 1, 2)))
    with pytest.raises(ValueError, match="delete"):
        _apply_table_deltas(resp, DESC, {1: "IT_ROWS"}, params)


def test_an_edit_for_a_table_not_sent_is_refused() -> None:
    resp = _delta((0x0332, struct.pack(">III", 5, 7, 1)))
    with pytest.raises(ValueError, match="did not send"):
        _apply_table_deltas(resp, DESC, {1: "IT_ROWS"}, {"IT_ROWS": [{"TEXT": "A"}]})


@pytest.mark.integration
@pytest.mark.skipif(
    not __import__("os").environ.get("SAPRFC_ASHOST"), reason="needs a live SAP system"
)
def test_live_stfc_structure_returns_the_edited_table() -> None:
    # STFC_STRUCTURE appends one row to the RFCTABLE it receives; the reply carries
    # that as an append edit, and the reference client returns both rows.
    import os

    import saprfclib

    with saprfclib.connect(
        ashost=os.environ["SAPRFC_ASHOST"],
        sysnr=os.environ.get("SAPRFC_SYSNR", "00"),
        client=os.environ.get("SAPRFC_CLIENT", "001"),
        user=os.environ["SAPRFC_USER"],
        passwd=os.environ["SAPRFC_PASSWD"],
    ) as conn:
        r = conn.call(
            "STFC_STRUCTURE", IMPORTSTRUCT={"RFCCHAR4": "ABCD"}, RFCTABLE=[{"RFCCHAR4": "ROW1"}]
        )
    assert len(r["RFCTABLE"]) == 2
    assert r["RFCTABLE"][0]["RFCCHAR4"] == "ROW1"
