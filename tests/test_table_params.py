# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""TABLES-parameter regression tests (issues #9, #10, #11, #12).

RFC_GET_FUNCTION_INTERFACE declares a TABLES parameter with the EXID of its row
*structure* (``EXID='u'``) and ``PARAMCLASS='T'``.  Typing the parameter from EXID
alone mistypes every TABLES param as a bare structure, which routes it through the
scalar 0x0201/0x0203 TLV pair on the way out and decodes concatenated row bytes as
a single struct on the way back.

Ground truth for what the wire actually carries is the golden capture
``tests/golden/framing/rfc_read_table_response.bin``: a live RFC_READ_TABLE
response whose DATA / FIELDS / OPTIONS params (all PARAMCLASS 'T') arrive as the
table tag sequence 0x0301 / 0x0330 / 0x0302 / 0x0304, never as 0x0203 values.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from saprfclib.codec import RFCTYPE_CHAR, RFCTYPE_STRUCTURE, RFCTYPE_TABLE, encode
from saprfclib.invoke import build_invoke_request, parse_invoke_response
from saprfclib.metadata import _parse_params_row
from saprfclib.types import RFC_EXPORT, RFC_IMPORT, RFC_TABLES, FieldDesc, FunctionDesc, TypeDesc

GOLDEN = Path(__file__).parent / "golden" / "framing"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _params_row(
    *,
    parameter: str,
    paramclass: str,
    exid: str,
    intlength: int = 0,
    offset: int = 0,
    tabname: str = "",
    fieldname: str = "",
) -> dict[str, object]:
    """A GFI PARAMS row as _parse_gfi_params_rows hands it to _parse_params_row."""
    return {
        "PARAMETER": parameter,
        "PARAMCLASS": paramclass,
        "EXID": exid,
        "INTLENGTH": intlength,
        "OFFSET": offset,
        "DECIMALS": 0,
        "TABNAME": tabname,
        "FIELDNAME": fieldname,
    }


def _char(name: str, uc_length: int, uc_offset: int) -> FieldDesc:
    return FieldDesc(
        name=name,
        rfctype=RFCTYPE_CHAR,
        nuc_length=uc_length // 2,
        nuc_offset=uc_offset // 2,
        uc_length=uc_length,
        uc_offset=uc_offset,
        decimals=0,
        unicode_mode=True,
    )


def _rfc_db_fld() -> TypeDesc:
    """RFC_READ_TABLE's FIELDS row layout, 206 bytes UC.

    Confirmed against golden rfc_read_table_response.bin: the FIELDS table's
    0x0302 info record declares row_size=0xce=206, and the field widths below sum
    to exactly that (30+6+6+1+60 chars = 103 chars = 206 UTF-16LE bytes).
    """
    return TypeDesc(
        name="RFC_DB_FLD",
        fields=[
            _char("FIELDNAME", 60, 0),
            _char("OFFSET", 12, 60),
            _char("LENGTH", 12, 72),
            _char("TYPE", 2, 84),
            _char("FIELDTEXT", 120, 86),
        ],
        nuc_size=103,
        uc_size=206,
    )


def _tab512() -> TypeDesc:
    """RFC_READ_TABLE's DATA row layout: a single WA CHAR(512) field, 1024 B UC.

    Golden rfc_read_table_response.bin declares row_size=0x400=1024 for DATA.
    """
    return TypeDesc(name="TAB512", fields=[_char("WA", 1024, 0)], nuc_size=512, uc_size=1024)


def _read_table_desc() -> FunctionDesc:
    """RFC_READ_TABLE descriptor with TABLES params correctly typed as TABLE."""
    return FunctionDesc(
        name="RFC_READ_TABLE",
        parameters=[
            FieldDesc(
                name="QUERY_TABLE",
                rfctype=RFCTYPE_CHAR,
                nuc_length=30,
                nuc_offset=0,
                uc_length=60,
                uc_offset=0,
                decimals=0,
                direction=RFC_IMPORT,
            ),
            FieldDesc(
                name="DATA",
                rfctype=RFCTYPE_TABLE,
                nuc_length=0,
                nuc_offset=0,
                uc_length=0,
                uc_offset=0,
                decimals=0,
                direction=RFC_TABLES,
                type_desc=_tab512(),
            ),
            FieldDesc(
                name="FIELDS",
                rfctype=RFCTYPE_TABLE,
                nuc_length=0,
                nuc_offset=0,
                uc_length=0,
                uc_offset=0,
                decimals=0,
                direction=RFC_TABLES,
                type_desc=_rfc_db_fld(),
            ),
        ],
    )


# --------------------------------------------------------------------------- #
# #9 / #10 — TABLES direction decides the rfctype, not EXID
# --------------------------------------------------------------------------- #


def test_tables_param_is_typed_as_table_not_structure() -> None:
    """A PARAMCLASS 'T' row is a TABLE even though its EXID names a structure."""
    fd = _parse_params_row(
        _params_row(parameter="FIELDS", paramclass="T", exid="u", tabname="RFC_DB_FLD")
    )
    assert fd.direction == RFC_TABLES
    assert fd.rfctype == RFCTYPE_TABLE


def test_non_tables_structure_param_stays_a_structure() -> None:
    """The promotion is keyed on direction — an IMPORT structure is untouched."""
    fd = _parse_params_row(
        _params_row(parameter="IMPORTSTRUCT", paramclass="I", exid="u", tabname="RFCTEST")
    )
    assert fd.rfctype == RFCTYPE_STRUCTURE


def test_nested_field_row_keeps_its_exid_type() -> None:
    """Nested rows (non-blank FIELDNAME) describe fields inside the row structure.

    They repeat the parent's PARAMCLASS, so promoting on direction alone would
    retype a plain CHAR column as a table.
    """
    fd = _parse_params_row(
        _params_row(
            parameter="FIELDS",
            paramclass="T",
            exid="C",
            intlength=60,
            tabname="RFC_DB_FLD",
            fieldname="FIELDNAME",
        )
    )
    assert fd.rfctype == RFCTYPE_CHAR


def test_tables_param_emits_table_tlv_tags_not_a_scalar_value() -> None:
    """Encode side: a TABLE param must produce 0x0301/0x0330/0x0302/0x0303/0x0306.

    With rfctype=STRUCTURE the builder falls through to the scalar 0x0201/0x0203
    pair, which the server rejects as CALL_FUNCTION_ILLEGAL_P_TYPE.
    """
    desc = _read_table_desc()
    req = build_invoke_request(
        "RFC_READ_TABLE",
        desc,
        {"QUERY_TABLE": "T000", "FIELDS": [{"FIELDNAME": "MANDT"}]},
        version="754",
    )
    tags = {tag for tag, _ in _walk_tlv(req)}
    assert 0x0301 in tags, "table name tag missing"
    assert 0x0302 in tags, "table info tag missing"
    assert 0x0303 in tags, "table row tag missing"
    assert 0x0306 in tags, "table end tag missing"

    # The FIELDS row must not also appear as a scalar 0x0203 value.
    names = [val for tag, val in _walk_tlv(req) if tag == 0x0201]
    assert b"F\x00I\x00E\x00L\x00D\x00S\x00" not in names


def _walk_tlv(data: bytes) -> list[tuple[int, bytes]]:
    """Minimal TLV walk mirroring the reader in invoke._extract_name_value_pairs."""
    out: list[tuple[int, bytes]] = []
    pos, n = 0, len(data)
    while pos + 4 <= n:
        tag, length = struct.unpack_from(">HH", data, pos)
        pos += 4
        if tag == 0xFFFF:
            break
        if length == 0xFFFF:
            length = struct.unpack_from(">I", data, pos)[0]
            pos += 4
        val = data[pos : pos + length]
        pos += length
        if pos + 2 <= n and struct.unpack_from(">H", data, pos)[0] == tag:
            pos += 2
        out.append((tag, val))
    return out


# --------------------------------------------------------------------------- #
# #9 / #12 — decode side, driven by the golden capture
# --------------------------------------------------------------------------- #


def test_golden_rfc_read_table_response_decodes_tables_as_row_lists() -> None:
    """Replay the live RFC_READ_TABLE response and check both TABLES params.

    Source: tests/golden/framing/rfc_read_table_response.bin (live capture).
    The DATA table declares 2 rows of 1024 B and FIELDS declares 17 rows of 206 B.
    """
    raw = (GOLDEN / "rfc_read_table_response.bin").read_bytes()
    # Fixture is stored NI-framed: 4-byte BE payload length, then the GW frame.
    assert struct.unpack_from(">I", raw, 0)[0] == len(raw) - 4
    payload = raw[4:]
    assert payload[0] == 0x06, "expected a GW frame"
    tlv = payload[80:]  # 76-byte GW header + 4-byte RFC marker

    result = parse_invoke_response(tlv, _read_table_desc())

    assert isinstance(result["DATA"], list)
    assert len(result["DATA"]) == 2
    assert isinstance(result["DATA"][0], dict)
    # T000 client rows: the first column of the flat WA is the client number.
    assert result["DATA"][0]["WA"].startswith("000|")
    assert result["DATA"][1]["WA"].startswith("001|")

    assert isinstance(result["FIELDS"], list)
    assert len(result["FIELDS"]) == 17
    assert result["FIELDS"][0]["FIELDNAME"] == "MANDT"
    assert result["FIELDS"][1]["FIELDNAME"] == "MTEXT"
    assert [row["FIELDNAME"] for row in result["FIELDS"]][-1] == "LOGSYS"


def test_golden_response_would_be_mistyped_as_a_single_struct() -> None:
    """Guard the regression: STRUCTURE typing collapses 17 rows into one dict.

    This is what issue #9 reported as "BAPI calls return empty results" — the
    concatenated row bytes decode as a single work area and every row past the
    first is silently dropped.
    """
    raw = (GOLDEN / "rfc_read_table_response.bin").read_bytes()
    tlv = raw[4:][80:]

    desc = _read_table_desc()
    for field in desc.parameters:
        if field.name == "FIELDS":
            field.rfctype = RFCTYPE_STRUCTURE  # the pre-fix state

    mistyped = parse_invoke_response(tlv, desc)
    assert isinstance(mistyped["FIELDS"], dict)  # not a list — data lost


# --------------------------------------------------------------------------- #
# #11 — partial row dicts fill with type-appropriate initial values
# --------------------------------------------------------------------------- #


def test_partial_row_dict_encodes_without_keyerror() -> None:
    """RFC_READ_TABLE's canonical usage: set FIELDNAME, leave the rest unset."""
    field = FieldDesc(
        name="FIELDS",
        rfctype=RFCTYPE_TABLE,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        direction=RFC_TABLES,
        type_desc=_rfc_db_fld(),
    )
    raw = encode(RFCTYPE_TABLE, [{"FIELDNAME": "BNAME"}, {"FIELDNAME": "BCODE"}], field)
    assert len(raw) == 206 * 2


def test_unset_char_fields_are_blank_padded_not_nul_filled() -> None:
    """CHAR pads with blanks; leaving the buffer's NUL fill would corrupt the row.

    Fixed-width character fields are blank-padded and numeric fields zero-padded —
    the two are not interchangeable, so an unset field has to be encoded, not
    skipped.
    """
    field = FieldDesc(
        name="FIELDS",
        rfctype=RFCTYPE_TABLE,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        direction=RFC_TABLES,
        type_desc=_rfc_db_fld(),
    )
    raw = encode(RFCTYPE_TABLE, [{"FIELDNAME": "BNAME"}], field)

    fieldname = raw[0:60].decode("utf-16-le")
    assert fieldname == "BNAME" + " " * 25

    fieldtext = raw[86:206].decode("utf-16-le")
    assert fieldtext == " " * 60, "unset CHAR must be blank-padded, not NUL-filled"


def test_supplied_fields_still_win_over_defaults() -> None:
    """Defaulting must not shadow a value the caller did supply."""
    field = FieldDesc(
        name="FIELDS",
        rfctype=RFCTYPE_TABLE,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        direction=RFC_TABLES,
        type_desc=_rfc_db_fld(),
    )
    raw = encode(RFCTYPE_TABLE, [{"FIELDNAME": "BNAME", "TYPE": "C"}], field)
    assert raw[84:86].decode("utf-16-le") == "C"


def test_partial_dict_roundtrips_through_decode() -> None:
    """decode(encode(partial)) yields the full row with initial values filled in."""
    from saprfclib.codec import decode

    field = FieldDesc(
        name="FIELDS",
        rfctype=RFCTYPE_TABLE,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        direction=RFC_TABLES,
        type_desc=_rfc_db_fld(),
    )
    raw = encode(RFCTYPE_TABLE, [{"FIELDNAME": "BNAME"}], field)
    rows = decode(RFCTYPE_TABLE, raw, field)
    assert rows == [{"FIELDNAME": "BNAME", "OFFSET": "", "LENGTH": "", "TYPE": "", "FIELDTEXT": ""}]


@pytest.mark.parametrize(
    ("rfctype", "expected"),
    [
        (8, 0),  # RFCTYPE_INT
        (9, 0),  # RFCTYPE_INT2
        (10, 0),  # RFCTYPE_INT1
        (31, 0),  # RFCTYPE_INT8
        (7, 0.0),  # RFCTYPE_FLOAT
        (4, b""),  # RFCTYPE_BYTE
        (30, b""),  # RFCTYPE_XSTRING
        (0, ""),  # RFCTYPE_CHAR
        (6, ""),  # RFCTYPE_NUM
        (29, ""),  # RFCTYPE_STRING
        (5, []),  # RFCTYPE_TABLE
        (17, {}),  # RFCTYPE_STRUCTURE
    ],
)
def test_default_field_value_per_type(rfctype: int, expected: object) -> None:
    """Each type's unset value is the one its encoder expects."""
    from decimal import Decimal

    from saprfclib.codec import _default_field_value

    field = FieldDesc(
        name="F",
        rfctype=rfctype,
        nuc_length=1,
        nuc_offset=0,
        uc_length=2,
        uc_offset=0,
        decimals=0,
    )
    assert _default_field_value(field) == expected

    field.rfctype = 2  # RFCTYPE_BCD
    assert _default_field_value(field) == Decimal(0)


# --------------------------------------------------------------------------- #
# #12 — the metadata bootstrap must attach type_desc to TABLE params too
# --------------------------------------------------------------------------- #


def test_export_table_param_is_declared_but_not_sent_as_data() -> None:
    """An EXPORT-direction table is declared via 0x0205 and carries no row data.

    Matches golden rfc_read_table_request.bin, where the empty DATA / FIELDS /
    OPTIONS tables appear only as 0x0205 declarations.
    """
    desc = FunctionDesc(
        name="RFC_READ_TABLE",
        parameters=[
            FieldDesc(
                name="DATA",
                rfctype=RFCTYPE_TABLE,
                nuc_length=0,
                nuc_offset=0,
                uc_length=0,
                uc_offset=0,
                decimals=0,
                direction=RFC_EXPORT,
                type_desc=_tab512(),
            ),
        ],
    )
    req = build_invoke_request("RFC_READ_TABLE", desc, {}, version="754")
    tags = {tag for tag, _ in _walk_tlv(req)}
    assert 0x0205 in tags
    assert 0x0301 not in tags
