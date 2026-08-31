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

import logging
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


def test_fieldname_does_not_gate_the_promotion() -> None:
    """FIELDNAME names the DDIC source field, not a nesting level.

    Live GFI rows on kernel 793 show plain top-level parameters carrying a
    FIELDNAME: DELIMITER is SONV-FLAG, QUERY_TABLE is DD02L-TABNAME. Gating the
    TABLES promotion on a blank FIELDNAME would therefore fail for any TABLES
    parameter whose line type derives from a data element, silently restoring the
    STRUCTURE mistyping this promotion exists to fix.
    """
    fd = _parse_params_row(
        _params_row(
            parameter="SOMETABLE",
            paramclass="T",
            exid="u",
            tabname="SOMESTRUCT",
            fieldname="SOMEFIELD",
        )
    )
    assert fd.rfctype == RFCTYPE_TABLE


def test_scalar_param_with_a_fieldname_is_unaffected() -> None:
    """A top-level CHAR parameter keeps CHAR even though FIELDNAME is set.

    Mirrors the live DELIMITER row: PARAMCLASS 'I', EXID 'C', TABNAME 'SONV',
    FIELDNAME 'FLAG'.
    """
    fd = _parse_params_row(
        _params_row(
            parameter="DELIMITER",
            paramclass="I",
            exid="C",
            intlength=2,
            tabname="SONV",
            fieldname="FLAG",
        )
    )
    assert fd.rfctype == RFCTYPE_CHAR
    assert fd.uc_length == 2


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


# --------------------------------------------------------------------------- #
# GFI parameter widths — no double-scaling on a Unicode connection
# --------------------------------------------------------------------------- #
#
# OFFSET / INTLENGTH arrive in the character width the connection uses. On a
# Unicode connection they are already Unicode byte counts; scaling them again
# emitted parameter values at twice their declared width. The server discarded
# them silently — observed live on kernel 793 as RFC_READ_TABLE raising
# TABLE_NOT_AVAILABLE because QUERY_TABLE never arrived intact.


def _gfi_row(parameter: str, exid: str, intlength: int) -> bytes:
    """One 402-byte GFI PARAMS row as the server puts it on the wire."""

    def pad(text: str, chars: int) -> bytes:
        enc = text.encode("utf-16-le")[: chars * 2]
        return enc + b"\x00\x00" * (chars - len(enc) // 2)

    row = bytearray()
    row += pad("I", 1)  # PARAMCLASS
    row += pad(parameter, 30)
    row += pad("", 30)  # TABNAME
    row += pad("", 30)  # FIELDNAME
    row += pad(exid, 1)
    row += struct.pack("<I", 1)  # POSITION
    row += struct.pack("<I", 0)  # OFFSET
    row += struct.pack("<I", intlength)
    row += struct.pack("<I", 0)  # DECIMALS
    row += pad("", 21) + pad("", 79) + pad("", 1)
    assert len(row) == 402
    return bytes(row)


def _gfi_response(rows: list[bytes]) -> bytes:
    from saprfclib.invoke import tlv_record

    body = b"".join(tlv_record(0x0303, r) for r in rows)
    body += struct.pack(">HH", 0xFFFF, 0) + struct.pack(">H", 0xFFFF)
    return b"\x06\xcb" + b"\x00" * 78 + body


@pytest.mark.parametrize(("exid", "wire_length"), [("C", 60), ("C", 2), ("N", 8), ("D", 16)])
def test_unicode_gfi_lengths_are_not_rescaled(exid: str, wire_length: int) -> None:
    """A Unicode connection reports uc bytes; they must survive unchanged."""
    from saprfclib.connection import _parse_gfi_params_rows

    rows = _parse_gfi_params_rows(
        _gfi_response([_gfi_row("P", exid, wire_length)]), unicode_mode=True
    )
    assert rows[0]["INTLENGTH"] == wire_length


def test_query_table_encodes_to_the_golden_width() -> None:
    """DD02L-TABNAME is CHAR(30); the golden capture's 0x0203 value is 60 bytes.

    Source: tests/golden/framing/rfc_read_table_request.bin.
    """
    from saprfclib.connection import _parse_gfi_params_rows

    rows = _parse_gfi_params_rows(
        _gfi_response([_gfi_row("QUERY_TABLE", "C", 60)]), unicode_mode=True
    )
    fd = _parse_params_row(rows[0])
    assert fd.uc_length == 60
    assert len(encode(fd.rfctype, "T000", fd)) == 60


def test_delimiter_encodes_to_the_golden_width() -> None:
    """SONV-FLAG is CHAR(1); the golden capture's 0x0203 value is 2 bytes."""
    from saprfclib.connection import _parse_gfi_params_rows

    rows = _parse_gfi_params_rows(_gfi_response([_gfi_row("DELIMITER", "C", 2)]), unicode_mode=True)
    fd = _parse_params_row(rows[0])
    assert fd.uc_length == 2
    assert len(encode(fd.rfctype, "|", fd)) == 2


def test_golden_request_scalar_widths_are_the_oracle() -> None:
    """Read the widths straight out of the capture so the numbers above are pinned."""
    raw = (GOLDEN / "rfc_read_table_request.bin").read_bytes()
    body = raw[4:][80:]
    widths: dict[str, int] = {}
    name = None
    for tag, val in _walk_tlv(body):
        if tag == 0x0201:
            name = val.decode("utf-16-le")
        elif tag == 0x0203 and name is not None:
            widths[name] = len(val)
            name = None
    assert widths["QUERY_TABLE"] == 60
    assert widths["DELIMITER"] == 2


def test_no_end_tag_after_table_rows() -> None:
    """A request must not carry 0x0306. Verified live on kernel 793.

    The SDK's table serializer writes name, DM id, info and rows and nothing else,
    and neither golden capture contains 0x0306 in a request. Sending one makes the
    server abort: the call comes back as an 80-byte header-only frame and every later
    call on that connection fails with "Conversation NNN not found". Dropping the tag
    is the single change that turns the same call into a success.
    """
    desc = _read_table_desc()
    req = build_invoke_request(
        "RFC_READ_TABLE",
        desc,
        {"QUERY_TABLE": "T000", "FIELDS": [{"FIELDNAME": "MANDT"}]},
        version="754",
    )
    assert 0x0306 not in {tag for tag, _ in _walk_tlv(req)}


def test_client_sent_table_returns_under_the_delta_tag() -> None:
    """A table the client sent comes back under 0x0335, keyed by DM table ID.

    Source: tests/golden/framing/rfc_read_table_delta_response.bin. DATA and OPTIONS —
    tables the client did not send — arrive under 0x0301 with their names; FIELDS,
    which the client did send with dm_table_id 1, arrives under 0x0335 instead.
    """
    from saprfclib.invoke import _extract_name_value_pairs

    body = (GOLDEN / "rfc_read_table_delta_response.bin").read_bytes()[80:]
    pairs = dict(_extract_name_value_pairs(body, {1: "FIELDS"}))
    assert set(pairs) == {"DATA", "OPTIONS", "FIELDS"}
    assert len(pairs["FIELDS"]) == 4 * 206  # four rows of RFC_DB_FLD


def test_delta_header_is_opcode_dm_id_and_row_count() -> None:
    """0x0335 carries three BE uint32: [10, dm_table_id, row_count] — not a name.

    Reading it as a UTF-16LE name is a trap: the header is 12 bytes, exactly the
    width of "FIELDS" encoded UTF-16LE, so a length check alone cannot tell them
    apart. Confirmed by varying the row count against a fixed DM id.
    """
    body = (GOLDEN / "rfc_read_table_delta_response.bin").read_bytes()[80:]
    header = next(val for tag, val in _walk_tlv(body) if tag == 0x0335)
    assert len(header) == 12
    opcode, dm_id, row_count = struct.unpack(">III", header)
    assert (opcode, dm_id, row_count) == (10, 1, 4)


def test_delta_table_is_skipped_when_the_dm_id_is_unknown() -> None:
    """Without the mapping we cannot name the table, so its rows are not guessed."""
    from saprfclib.invoke import _extract_name_value_pairs

    body = (GOLDEN / "rfc_read_table_delta_response.bin").read_bytes()[80:]
    pairs = dict(_extract_name_value_pairs(body))  # no dm_table_names
    assert "FIELDS" not in pairs
    assert set(pairs) == {"DATA", "OPTIONS"}


def test_dm_table_ids_numbers_only_tables_that_carry_rows() -> None:
    """IDs run from 1 in parameter order, skipping empty and EXPORT-only tables."""
    from saprfclib.invoke import dm_table_ids

    desc = _read_table_desc()
    params = {"QUERY_TABLE": "T000", "FIELDS": [{"FIELDNAME": "MANDT"}]}
    assert dm_table_ids(desc, params) == {1: "FIELDS"}
    # DATA is declared before FIELDS; supplying rows for it takes id 1.
    both = {"DATA": [{"WA": "x"}], "FIELDS": [{"FIELDNAME": "MANDT"}]}
    assert dm_table_ids(desc, both) == {1: "DATA", 2: "FIELDS"}
    assert dm_table_ids(desc, {"FIELDS": []}) == {}


def test_request_dm_id_matches_what_the_response_echoes() -> None:
    """The id we write in 0x0330 is the id the server sends back in 0x0335.

    Sources: rfc_read_table_delta_request.bin / rfc_read_table_delta_response.bin.
    """
    req = (GOLDEN / "rfc_read_table_delta_request.bin").read_bytes()[80:]
    resp = (GOLDEN / "rfc_read_table_delta_response.bin").read_bytes()[80:]
    sent_dm = struct.unpack(">I", next(v for t, v in _walk_tlv(req) if t == 0x0330))[0]
    _, echoed_dm, _ = struct.unpack(">III", next(v for t, v in _walk_tlv(resp) if t == 0x0335))
    assert sent_dm == echoed_dm == 1


def test_golden_delta_request_carries_no_end_tag() -> None:
    """The capture of a successful table-bearing call contains no 0x0306."""
    req = (GOLDEN / "rfc_read_table_delta_request.bin").read_bytes()[80:]
    tags = [tag for tag, _ in _walk_tlv(req)]
    assert 0x0301 in tags and 0x0330 in tags and 0x0303 in tags
    assert 0x0306 not in tags


# --------------------------------------------------------------------------- #
# Silent-failure guards
# --------------------------------------------------------------------------- #
#
# Each of these turned a wire-level fault into a confusing error in caller code
# during the live debugging of this module.


def test_response_without_a_return_code_raises() -> None:
    """An aborted call must not read as an empty successful result.

    Live shape: the gateway tears down the conversation and answers with an
    80-byte frame carrying no TLV body at all. That used to reach the caller as
    ``{}``, so the real failure surfaced later as a KeyError on a missing
    parameter — and the dead connection stayed in use.
    """
    from saprfclib.exceptions import CommunicationError

    with pytest.raises(CommunicationError, match="empty frame"):
        parse_invoke_response(b"", _read_table_desc())


def test_response_with_only_a_terminator_raises() -> None:
    """A syntactically valid but empty TLV stream is still not a result."""
    from saprfclib.exceptions import CommunicationError

    with pytest.raises(CommunicationError, match="no return-code TLV"):
        parse_invoke_response(struct.pack(">HH", 0xFFFF, 0), _read_table_desc())


def test_exception_response_is_still_classified_before_the_return_code_check() -> None:
    """An ABAP exception carries no 0x0420 — it must raise the typed error, not
    the malformed-response error."""
    from saprfclib.exceptions import AbapApplicationError
    from saprfclib.invoke import tlv_record

    resp = (
        tlv_record(0x0500)
        + tlv_record(0x0417, "131".encode("utf-16-le"))
        + tlv_record(0x0401, "TABLE_NOT_AVAILABLE".encode("utf-16-le"))
        + struct.pack(">HH", 0xFFFF, 0)
    )
    with pytest.raises(AbapApplicationError):
        parse_invoke_response(resp, _read_table_desc())


def test_success_response_with_no_output_params_is_an_empty_dict() -> None:
    """rc=0 and nothing else is a legitimate empty result, not an error."""
    from saprfclib.invoke import tlv_record

    resp = tlv_record(0x0420, struct.pack(">I", 0)) + struct.pack(">HH", 0xFFFF, 0)
    assert parse_invoke_response(resp, _read_table_desc()) == {}


def test_unknown_parameter_name_is_rejected_not_dropped() -> None:
    """Passing an argument the interface does not declare must fail loudly.

    The builder iterates the descriptor, so an unknown name simply never matched
    and the value vanished from the request — the server then ran the function
    without it and returned nothing for it.
    """
    with pytest.raises(ValueError, match="not in the function interface"):
        build_invoke_request(
            "RFC_READ_TABLE", _read_table_desc(), {"QUERY_TABLE": "T000", "NOSUCHPARAM": "x"}
        )


def test_known_parameters_are_still_accepted() -> None:
    """The guard must not reject valid names, in any case form."""
    req = build_invoke_request(
        "RFC_READ_TABLE",
        _read_table_desc(),
        {"query_table": "T000", "FIELDS": [{"FIELDNAME": "MANDT"}]},
    )
    assert 0x0301 in {tag for tag, _ in _walk_tlv(req)}


def test_exception_rows_are_recognised_deliberately() -> None:
    """PARAMCLASS 'X' rows describe exceptions, not parameters.

    Live names from RFC_READ_TABLE on kernel 793.
    """
    from saprfclib.metadata import is_exception_row

    for name in (
        "DATA_BUFFER_EXCEEDED",
        "FIELD_NOT_VALID",
        "NOT_AUTHORIZED",
        "OPTION_NOT_VALID",
        "TABLE_NOT_AVAILABLE",
        "TABLE_WITHOUT_DATA",
    ):
        assert is_exception_row(_params_row(parameter=name, paramclass="X", exid=""))
    assert not is_exception_row(_params_row(parameter="FIELDS", paramclass="T", exid="u"))
    assert not is_exception_row(_params_row(parameter="QUERY_TABLE", paramclass="I", exid="C"))


# --------------------------------------------------------------------------- #
# Compressed function metadata
# --------------------------------------------------------------------------- #
#
# The server compresses a table once it passes roughly 8 KB, so any function module
# with enough parameters — most BAPIs — sends its PARAMS table as SAPCOMPRESS
# fragments. Handling only the per-row form left every one of them with an empty
# descriptor and no diagnostic.


def _gfi_fixture() -> bytes:
    return (GOLDEN / "gfi_compressed_params_response.bin").read_bytes()[80:]


def test_compressed_params_table_yields_every_row() -> None:
    """All 44 rows of BAPI_USER_GET_DETAIL's metadata are recovered."""
    from saprfclib.connection import _parse_gfi_params_rows

    rows = _parse_gfi_params_rows(_gfi_fixture(), unicode_mode=True)
    assert len(rows) == 44
    assert rows[0]["PARAMETER"] == "ADDRESS"
    assert rows[0]["TABNAME"] == "BAPIADDR3"


def test_compressed_params_rows_all_parse_into_field_descs() -> None:
    """Row slicing is aligned — a wrong stride would corrupt every row after the first."""
    from saprfclib.connection import _parse_gfi_params_rows

    rows = _parse_gfi_params_rows(_gfi_fixture(), unicode_mode=True)
    descs = [_parse_params_row(r) for r in rows]
    assert len(descs) == 44
    assert {d.name for d in descs} >= {"ADDRESS", "ADMINDATA", "ALIAS", "COMPANY"}


def test_compressed_rows_are_sliced_by_the_declared_stride() -> None:
    """0x0302 declares 404 for a 402-byte layout; the stride comes from the wire."""
    from saprfclib.connection import _GFI_ROW_BYTES, _table_row_buffers

    buffers = _table_row_buffers(_gfi_fixture(), _GFI_ROW_BYTES, "PARAMS")
    assert len(buffers) == 44
    assert len(buffers[0]) == 404  # not the documented 402
    assert sum(len(b) for b in buffers) == 404 * 44


def test_lz_records_are_fragments_of_one_stream() -> None:
    """Each 0x0305 record decompresses to nothing on its own; joined they decode.

    Guards the specific mistake of treating every record as a self-contained block,
    which is what the reader used to do.
    """
    from saprfclib.invoke import decompress_table_stream

    chunks = [val for tag, val in _walk_tlv(_gfi_fixture()) if tag == 0x0305]
    assert len(chunks) == 8
    assert all(len(c) == 250 for c in chunks)
    with pytest.raises(ValueError):
        decompress_table_stream(chunks[:1], "PARAMS")
    assert len(decompress_table_stream(chunks, "PARAMS")) == 17776


def test_per_row_records_are_not_resliced() -> None:
    """Uncompressed rows keep their own boundaries even when 0x0302 is wider.

    A structure-definition response declared row_size 140 with 138-byte records;
    re-slicing by the stride would misalign everything after the first row.
    """
    from saprfclib.connection import _GFI_ROW_BYTES, _table_row_buffers
    from saprfclib.invoke import tlv_record

    row = b"\x00" * 402
    stream = (
        tlv_record(0x0301, "PARAMS".encode("utf-16-le"))
        + tlv_record(0x0302, struct.pack(">II", 404, 3))  # stride wider than records
        + tlv_record(0x0303, row)
        + tlv_record(0x0303, row)
        + tlv_record(0x0303, row)
        + struct.pack(">HH", 0xFFFF, 0)
    )
    buffers = _table_row_buffers(stream, _GFI_ROW_BYTES, "PARAMS")
    assert [len(b) for b in buffers] == [402, 402, 402]


# --------------------------------------------------------------------------- #
# Server-direction TABLE output (SERVER-04)
# --------------------------------------------------------------------------- #
#
# The server used to serialize every output parameter as a 0x0201/0x0203 pair,
# tables included — the server-direction twin of the client mistyping that produced
# CALL_FUNCTION_ILLEGAL_P_TYPE.


def _server_desc() -> FunctionDesc:
    return FunctionDesc(
        name="Z_TEST",
        parameters=[
            FieldDesc("ECHOTEXT", RFCTYPE_CHAR, 10, 0, 20, 0, 0, direction=RFC_EXPORT),
            FieldDesc(
                "ROWS",
                RFCTYPE_TABLE,
                0,
                0,
                0,
                0,
                0,
                direction=RFC_TABLES,
                type_desc=_rfc_db_fld(),
            ),
        ],
    )


def test_server_emits_tables_with_the_table_protocol() -> None:
    """A TABLE output must use 0x0301/0x0330/0x0302/0x0304, never a 0x0203 value."""
    from saprfclib.server import RfcServer

    body = RfcServer._build_response(
        RfcServer, _server_desc(), {"ECHOTEXT": "hi", "ROWS": [{"FIELDNAME": "MANDT"}]}
    )
    tags = [tag for tag, _ in _walk_tlv(body)]
    assert 0x0301 in tags and 0x0330 in tags and 0x0302 in tags and 0x0304 in tags
    # The scalar pair is still used for ECHOTEXT, and only for it.
    assert tags.count(0x0201) == 1
    assert tags.count(0x0203) == 1


def test_server_table_row_info_matches_the_rows() -> None:
    """0x0302 must declare the real row size and count."""
    from saprfclib.server import RfcServer

    rows = [{"FIELDNAME": "MANDT"}, {"FIELDNAME": "MTEXT"}]
    body = RfcServer._build_response(RfcServer, _server_desc(), {"ROWS": rows})
    info = next(val for tag, val in _walk_tlv(body) if tag == 0x0302)
    row_size, row_count = struct.unpack(">II", info)
    assert (row_size, row_count) == (206, 2)
    payloads = [val for tag, val in _walk_tlv(body) if tag == 0x0304]
    assert [len(p) for p in payloads] == [206, 206]


def test_server_round_trips_through_the_client_reader() -> None:
    """What the server writes, the client's own extractor must read back."""
    from saprfclib.invoke import _extract_name_value_pairs
    from saprfclib.server import RfcServer

    rows = [{"FIELDNAME": "MANDT"}, {"FIELDNAME": "MTEXT"}]
    body = RfcServer._build_response(RfcServer, _server_desc(), {"ECHOTEXT": "hi", "ROWS": rows})
    pairs = dict(_extract_name_value_pairs(body))
    assert pairs["ROWS"] == encode(RFCTYPE_TABLE, rows, _server_desc().parameters[1])


def test_server_empty_table_is_declared_without_a_data_block() -> None:
    """An empty table needs its name only, mirroring the client side."""
    from saprfclib.server import RfcServer

    body = RfcServer._build_response(RfcServer, _server_desc(), {"ROWS": []})
    tags = [tag for tag, _ in _walk_tlv(body)]
    assert 0x0301 in tags
    assert 0x0302 not in tags and 0x0304 not in tags


def test_encoding_a_table_without_a_layout_names_the_parameter() -> None:
    """The old bare assert said nothing and vanished under python -O."""
    desc = _read_table_desc()
    for f in desc.parameters:
        if f.name == "FIELDS":
            f.type_desc = None
    with pytest.raises(ValueError, match="FIELDS.*row layout"):
        build_invoke_request("RFC_READ_TABLE", desc, {"FIELDS": [{"FIELDNAME": "MANDT"}]})


# --------------------------------------------------------------------------- #
# INT4 wire byte order — CONFIRMED
# --------------------------------------------------------------------------- #


def test_int4_params_are_little_endian_on_the_wire() -> None:
    """STFC_CHANGING's captured exchange settles INT4 byte order by arithmetic.

    The function returns RESULT = START_VALUE + COUNTER and increments COUNTER.
    The request carries START_VALUE=0a000000 and COUNTER=01000000; the response
    carries RESULT=0b000000 and COUNTER=02000000. Read little-endian that is
    10 + 1 = 11 and 1 -> 2, exactly what the function does. Read big-endian the
    inputs would be 167772160 and 16777216, and no reading of the response makes
    the arithmetic work — so the server decoded our bytes as little-endian.

    Sources: tests/golden/framing/stfc_changing_request.bin and
    stfc_changing_response.bin.
    """
    values: dict[str, dict[str, int]] = {}
    for which in ("request", "response"):
        raw = (GOLDEN / f"stfc_changing_{which}.bin").read_bytes()
        if struct.unpack_from(">I", raw, 0)[0] == len(raw) - 4:
            raw = raw[4:]
        body = raw[80:] if raw[:1] == b"\x06" else raw
        found: dict[str, int] = {}
        name = None
        for tag, val in _walk_tlv(body):
            if tag == 0x0201:
                name = val.decode("utf-16-le").rstrip("\x00 ")
            elif tag == 0x0203 and name is not None and len(val) == 4:
                found[name] = struct.unpack("<i", val)[0]
                name = None
        values[which] = found

    start_value = values["request"]["START_VALUE"]
    counter_in = values["request"]["COUNTER"]
    result = values["response"]["RESULT"]
    counter_out = values["response"]["COUNTER"]

    assert (start_value, counter_in) == (10, 1)
    assert result == start_value + counter_in  # 11
    assert counter_out == counter_in + 1  # 2


def test_int4_encoder_reproduces_the_captured_bytes() -> None:
    """encode() must emit exactly what the capture shows for the same values."""
    field = FieldDesc("START_VALUE", 8, 4, 0, 4, 0, 0, direction=RFC_IMPORT)
    assert encode(8, 10, field) == bytes.fromhex("0a000000")
    assert encode(8, 1, field) == bytes.fromhex("01000000")


# --------------------------------------------------------------------------- #
# strict_params — unknown keyword arguments (issue #24)
# --------------------------------------------------------------------------- #


def _sxpg_desc() -> FunctionDesc:
    return FunctionDesc(
        "SXPG_STEP_XPG_START",
        [FieldDesc("COMMANDNAME", RFCTYPE_CHAR, 10, 0, 20, 0, 0, direction=RFC_IMPORT)],
    )


def test_lenient_mode_drops_undeclared_parameters() -> None:
    """Default policy: the call proceeds without the unrecognised argument."""
    from saprfclib.connection import _filter_call_params

    out = _filter_call_params(
        "SXPG_STEP_XPG_START",
        _sxpg_desc(),
        {"COMMANDNAME": "LIST_DB2DUMP", "MXROW": 100},
        strict=False,
        seen=set(),
    )
    assert out == {"COMMANDNAME": "LIST_DB2DUMP"}


def test_strict_mode_leaves_params_for_the_builder_to_reject() -> None:
    """strict=True passes them through so build_invoke_request names them."""
    from saprfclib.connection import _filter_call_params

    params = {"COMMANDNAME": "LIST_DB2DUMP", "MXROW": 100}
    assert (
        _filter_call_params(
            "SXPG_STEP_XPG_START", _sxpg_desc(), dict(params), strict=True, seen=set()
        )
        == params
    )
    with pytest.raises(ValueError, match="MXROW"):
        build_invoke_request("SXPG_STEP_XPG_START", _sxpg_desc(), params)


def test_dropping_warns_once_then_debugs(caplog: pytest.LogCaptureFixture) -> None:
    """A dropped argument must be visible, without flooding a long-running loop.

    Silent parameter loss is the failure mode that makes a call return results the
    caller never asked for, so the first occurrence is a WARNING; repeats of the same
    (function, names) combination fall to DEBUG.
    """
    from saprfclib.connection import _filter_call_params

    seen: set[tuple[str, tuple[str, ...]]] = set()
    params = {"COMMANDNAME": "X", "MXROW": 100}
    with caplog.at_level(logging.DEBUG, logger="saprfclib.connection"):
        for _ in range(3):
            _filter_call_params(
                "SXPG_STEP_XPG_START", _sxpg_desc(), dict(params), strict=False, seen=seen
            )
    levels = [r.levelno for r in caplog.records]
    assert levels.count(logging.WARNING) == 1
    assert levels.count(logging.DEBUG) == 2
    assert "MXROW" in caplog.records[0].getMessage()


def test_a_different_function_warns_again() -> None:
    """Deduplication is per function and per set of names, not global."""
    from saprfclib.connection import _filter_call_params

    seen: set[tuple[str, tuple[str, ...]]] = set()
    for func in ("F_ONE", "F_TWO"):
        _filter_call_params(func, _sxpg_desc(), {"MXROW": 1}, strict=False, seen=seen)
    assert seen == {("F_ONE", ("MXROW",)), ("F_TWO", ("MXROW",))}


def test_known_parameters_survive_both_modes() -> None:
    """The policy must never touch an argument the interface declares."""
    from saprfclib.connection import _filter_call_params

    for strict in (True, False):
        out = _filter_call_params(
            "SXPG_STEP_XPG_START",
            _sxpg_desc(),
            {"commandname": "lower-case is fine"},
            strict=strict,
            seen=set(),
        )
        assert out == {"commandname": "lower-case is fine"}


def test_strict_params_is_exposed_and_defaults_to_false() -> None:
    """SDK-parity default; opt in to strictness."""
    import inspect

    from saprfclib.connection import connect, connect_async

    for fn in (connect, connect_async):
        assert inspect.signature(fn).parameters["strict_params"].default is False


# --------------------------------------------------------------------------- #
# BASXML-encoded tables (issues #29 / #18)
# --------------------------------------------------------------------------- #
#
# RFC_READ_TABLE's ET_DATA arrives BASXML-encoded, not as a binary table.


def test_basxml_payload_is_ascii_not_utf16() -> None:
    """0x3c05 breaks the UTF-16LE convention every other string tag follows.

    '<ET_DATA>' is 9 bytes for 9 characters; decoding it as UTF-16LE yields mojibake,
    which is how it went unnoticed.
    """
    raw = (GOLDEN / "rfc_read_table_response.bin").read_bytes()
    if struct.unpack_from(">I", raw, 0)[0] == len(raw) - 4:
        raw = raw[4:]
    chunks = [val for tag, val in _walk_tlv(raw[80:]) if tag == 0x3C05]
    assert chunks[0] == b"<ET_DATA>"
    assert len(chunks[0]) == 9


# --------------------------------------------------------------------------- #
# BASXML table decoding (issue #29)
# --------------------------------------------------------------------------- #


def _basxml_desc() -> FunctionDesc:
    et = TypeDesc("SDTI_RESULT_TAB", [_char("LINE", 8, 0)], 4, 8)
    return FunctionDesc(
        "RFC_READ_TABLE",
        [
            FieldDesc("ET_DATA", RFCTYPE_TABLE, 0, 0, 0, 0, 0, direction=RFC_EXPORT, type_desc=et),
            FieldDesc(
                "DATA", RFCTYPE_TABLE, 0, 0, 0, 0, 0, direction=RFC_TABLES, type_desc=_tab512()
            ),
            FieldDesc(
                "FIELDS",
                RFCTYPE_TABLE,
                0,
                0,
                0,
                0,
                0,
                direction=RFC_TABLES,
                type_desc=_rfc_db_fld(),
            ),
        ],
    )


def test_basxml_table_reaches_the_caller() -> None:
    """ET_DATA decodes to rows instead of vanishing from the result.

    Source: tests/golden/framing/basxml_et_data_response.bin — RFC_READ_TABLE with
    USE_ET_DATA_4_RETURN='X'.
    """
    body = (GOLDEN / "basxml_et_data_response.bin").read_bytes()[80:]
    result = parse_invoke_response(body, _basxml_desc(), {1: "FIELDS"})
    assert "ET_DATA" in result
    assert len(result["ET_DATA"]) == 1
    assert list(result["ET_DATA"][0]) == ["LINE"]
    assert result["ET_DATA"][0]["LINE"].count("|") == 4  # five columns


def test_binary_data_table_is_empty_when_the_flag_is_set() -> None:
    """The server puts everything in ET_DATA and leaves DATA declared but empty."""
    body = (GOLDEN / "basxml_et_data_response.bin").read_bytes()[80:]
    result = parse_invoke_response(body, _basxml_desc(), {1: "FIELDS"})
    assert result["DATA"] == []
    assert len(result["FIELDS"]) == 4


def test_basxml_fragments_are_one_document_not_one_per_table() -> None:
    """Only the first fragment names the table; a later one may start with <item>.

    Re-deriving the name per chunk attributes the rows to a table called 'item' and
    loses them, which is exactly what happened first time round.
    """
    from saprfclib.invoke import _extract_name_value_pairs

    body = (GOLDEN / "basxml_et_data_response.bin").read_bytes()[80:]
    out: dict[str, bytes] = {}
    _extract_name_value_pairs(body, None, out)
    assert set(out) == {"ET_DATA"}
    assert out["ET_DATA"].startswith(b"<ET_DATA>")
    assert out["ET_DATA"].endswith(b"</ET_DATA>")


@pytest.mark.parametrize(
    ("xml", "expected"),
    [
        # the observed shortcut form: whole row in one element
        (b"<T><item><LINE>a|b</LINE></item></T>", [{"LINE": "a|b"}]),
        # the documented field-per-tag form
        (b"<T><item><A>1</A><B>2</B></item></T>", [{"A": "1", "B": "2"}]),
        # several rows
        (b"<T><item><L>r1</L></item><item><L>r2</L></item></T>", [{"L": "r1"}, {"L": "r2"}]),
        # empty table
        (b"<T></T>", []),
        # self-closing element -> empty value
        (b"<T><item><L/></item></T>", [{"L": ""}]),
        # entities must be resolved
        (b"<T><item><L>a&amp;b&lt;c&gt;d</L></item></T>", [{"L": "a&b<c>d"}]),
        (b"<T><item><L>&#65;&#x42;</L></item></T>", [{"L": "AB"}]),
    ],
)
def test_basxml_decoder_shapes(xml: bytes, expected: list[dict[str, str]]) -> None:
    """Both documented shapes, multiple rows, and entity handling."""
    from saprfclib.invoke import decode_basxml_table

    assert decode_basxml_table(xml, "T") == expected


def test_basxml_decoder_is_bounded() -> None:
    """Untrusted payload: refuse an absurd size rather than allocating for it."""
    from saprfclib.invoke import _BASXML_MAX_BYTES, decode_basxml_table

    with pytest.raises(ValueError, match="over the .* byte cap"):
        decode_basxml_table(b"x" * (_BASXML_MAX_BYTES + 1), "T")


def test_basxml_decoder_ignores_dtd_and_entity_declarations() -> None:
    """A hand-rolled scanner, so entity-expansion tricks have nothing to expand.

    Only the five predefined entities and numeric references resolve; an undeclared
    one is left as written rather than looked up.
    """
    from saprfclib.invoke import decode_basxml_table

    hostile = b"<!DOCTYPE T [<!ENTITY x 'boom'>]><T><item><L>&x;</L></item></T>"
    assert decode_basxml_table(hostile, "T") == [{"L": "&x;"}]


def test_binary_basxml_is_refused_not_misparsed() -> None:
    """SAP's binary BASXML shares a TLV tag with the plain-text form and nothing else.

    BasXmlRenderer writes a header beginning with the literal magic "BXML", then
    token bytes and a string table — an element open is the byte 0x3c followed by a
    string-table index, not the text "<". Feeding that to the text reader would
    produce nonsense, so it is refused with a pointer to the issue that tracks it.
    """
    from saprfclib.invoke import decode_basxml_table

    with pytest.raises(NotImplementedError, match="BXML magic"):
        decode_basxml_table(b"BXML\x3f\x03VER\x030.7", "ET_DATA")


def test_unidentifiable_xml_block_is_reported(caplog: pytest.LogCaptureFixture) -> None:
    """A block whose opening chunk is not text XML must not vanish silently."""
    from saprfclib.invoke import _extract_name_value_pairs, tlv_record

    stream = (
        tlv_record(0x3C02)
        + tlv_record(0x3C05, b"BXML\x3f\x03VER")
        + tlv_record(0x3C02)
        + struct.pack(">HH", 0xFFFF, 0)
    )
    out: dict[str, bytes] = {}
    with caplog.at_level(logging.WARNING, logger="saprfclib.invoke"):
        _extract_name_value_pairs(stream, None, out)
    assert out == {}
    assert any("issue #18" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# Unreadable responses and incomplete descriptors (issue #28)
# --------------------------------------------------------------------------- #


_GATEWAY_ERR = (
    b"*ERR*\x001\x00Conversation 50633926 not found\x00728\x00SAP-Gateway\x00793\x002"
    b"\x00/bas/793_REL/src/krn/si/gw/gwxxconn.c\x00960\x00\x00Wed Aug 26 12:18:35 2026"
    b"\x00\x00\x00\x003820\x00SAP-Gateway on host example / sapgw00\x00\x00\x00\x00\x00*ERR*\x00"
)


def test_gateway_error_frame_is_reported_as_such() -> None:
    """A torn-down conversation must not surface as a TLV parse error.

    The gateway answers with a NUL-separated *ERR* record, not TLV. Walking it as
    TLV reads '*E' as a tag and 'RR' as a length, which is the
    "malformed TLV: tag 0x2a45 length 21074" the reporter saw — an error that says
    nothing about what actually happened.
    """
    from saprfclib.exceptions import CommunicationError
    from saprfclib.invoke import raise_for_rfc_error

    with pytest.raises(CommunicationError) as excinfo:
        raise_for_rfc_error(_GATEWAY_ERR)
    message = str(excinfo.value)
    assert "Conversation 50633926 not found" in message
    assert "discarded" in message  # tells the caller the connection is dead


def test_gateway_error_text_is_extracted() -> None:
    """Message, component and kernel release come out of the NUL-separated record."""
    from saprfclib.invoke import parse_gateway_error

    text = parse_gateway_error(_GATEWAY_ERR)
    assert text is not None
    assert "Conversation 50633926 not found" in text
    assert "SAP-Gateway" in text


def test_a_normal_response_is_not_mistaken_for_a_gateway_error() -> None:
    from saprfclib.invoke import parse_gateway_error, tlv_record

    ok = tlv_record(0x0420, struct.pack(">I", 0)) + struct.pack(">HH", 0xFFFF, 0)
    assert parse_gateway_error(ok) is None
    assert parse_invoke_response(ok, _read_table_desc()) == {}


def test_unreadable_response_says_so_rather_than_quoting_a_bogus_tag() -> None:
    """Any payload that is not an RFC message at all gets a communication error."""
    from saprfclib.exceptions import CommunicationError
    from saprfclib.invoke import raise_for_rfc_error

    with pytest.raises(CommunicationError, match="not a readable RFC message"):
        raise_for_rfc_error(b"\x99\x99\xff\xf0garbage that is not TLV at all")


def test_missing_layout_raises_incomplete_descriptor_error() -> None:
    """A metadata gap gets its own type so callers can fall back on it.

    Distinct from AbapApplicationError: an unresolved layout is a client-side
    problem worth retrying against another backend, where an ABAP exception is the
    server's considered answer and is not.
    """
    from saprfclib.exceptions import IncompleteDescriptorError

    desc = _read_table_desc()
    for f in desc.parameters:
        if f.name == "FIELDS":
            f.type_desc = None
    with pytest.raises(IncompleteDescriptorError, match="FIELDS"):
        build_invoke_request("RFC_READ_TABLE", desc, {"FIELDS": [{"FIELDNAME": "MANDT"}]})


def test_incomplete_descriptor_error_is_catchable_both_ways() -> None:
    """Also a ValueError, so handlers written before it had a type keep working."""
    import saprfclib
    from saprfclib.exceptions import IncompleteDescriptorError, SapRfcError

    assert issubclass(IncompleteDescriptorError, SapRfcError)
    assert issubclass(IncompleteDescriptorError, ValueError)
    assert saprfclib.IncompleteDescriptorError is IncompleteDescriptorError


def test_decode_side_also_raises_the_typed_error() -> None:
    from saprfclib.codec import decode
    from saprfclib.exceptions import IncompleteDescriptorError

    field = FieldDesc("ROWS", RFCTYPE_TABLE, 0, 0, 0, 0, 0, direction=RFC_TABLES)
    with pytest.raises(IncompleteDescriptorError, match="ROWS"):
        decode(RFCTYPE_TABLE, b"\x00" * 8, field)


def test_multirow_xml_table_decodes_every_item() -> None:
    """Ten rows in one XML document — the case the single-row capture could not show.

    Source: tests/golden/framing/basxml_et_data_multirow_response.bin, a T100 read
    cross-checked against the binary path.
    """
    body = (GOLDEN / "basxml_et_data_multirow_response.bin").read_bytes()[80:]
    result = parse_invoke_response(body, _basxml_desc(), None)
    rows = result["ET_DATA"]
    assert len(rows) == 10
    assert all(list(r) == ["LINE"] for r in rows)
    assert rows[0]["LINE"].startswith("E|FL|001|")


def test_xml_fragments_do_not_split_on_item_boundaries() -> None:
    """Fragment boundaries are the server's choice, so joining first is required.

    Here the document arrives as 9 + 773 bytes: the first fragment holds only the
    opening tag, the second holds all ten items.
    """
    from saprfclib.invoke import _extract_name_value_pairs

    body = (GOLDEN / "basxml_et_data_multirow_response.bin").read_bytes()[80:]
    fragments = [val for tag, val in _walk_tlv(body) if tag == 0x3C05]
    assert len(fragments) == 2
    assert fragments[0] == b"<ET_DATA>"  # opening tag alone
    assert fragments[1].count(b"<item>") == 10

    out: dict[str, bytes] = {}
    _extract_name_value_pairs(body, None, out)
    assert out["ET_DATA"].count(b"<item>") == 10


def test_xml_rows_are_not_blank_padded() -> None:
    """The XML form omits the DDIC-width padding the binary form applies.

    Verified live: the identical query returns ARBGB as 'FL' here and as 'FL' plus
    eighteen spaces through DATA. Callers splitting the delimited row get trimmed
    values on this path and padded values on the other.
    """
    body = (GOLDEN / "basxml_et_data_multirow_response.bin").read_bytes()[80:]
    rows = parse_invoke_response(body, _basxml_desc(), None)["ET_DATA"]
    columns = rows[0]["LINE"].split("|")
    assert columns[1] == "FL"  # not 'FL' + 18 spaces
    assert all(c == c.rstrip() for c in columns[:3])


# --------------------------------------------------------------------------- #
# CPIC-layer refusal and anonymous connections
# --------------------------------------------------------------------------- #


def test_cpic_error_frame_is_decoded_not_reported_as_garbage() -> None:
    """A refusal below the RFC layer arrives in EBCDIC, not TLV.

    Source: tests/golden/framing/cpic_logon_error_response.bin — the reply to an
    RFC_PING sent with no logon frame at all on kernel 793.
    """
    from saprfclib.exceptions import CommunicationError
    from saprfclib.invoke import raise_for_rfc_error

    body = (GOLDEN / "cpic_logon_error_response.bin").read_bytes()[80:]
    with pytest.raises(CommunicationError, match="below the RFC layer") as excinfo:
        raise_for_rfc_error(body)
    assert "error during logon" in str(excinfo.value)


def test_cpic_detector_rejects_genuine_tlv_frames() -> None:
    """No false positives: a real response must never read as an EBCDIC error."""
    from saprfclib.invoke import parse_cpic_error

    for name in (
        "rfcping_response",
        "rfc_read_table_response",
        "gfi_fu_not_found_response",
        "server_response",
        "basxml_et_data_multirow_response",
    ):
        raw = (GOLDEN / f"{name}.bin").read_bytes()
        if len(raw) > 4 and struct.unpack_from(">I", raw, 0)[0] == len(raw) - 4:
            raw = raw[4:]
        assert parse_cpic_error(raw[80:]) is None, name


def test_cpic_padding_is_ascii_not_ebcdic() -> None:
    """The trailing padding is 0x20, so it must be stripped before decoding.

    Left in place it drags the printable ratio below the threshold and the frame is
    rejected as non-text — the detector would miss the very case it exists for.
    """
    body = (GOLDEN / "cpic_logon_error_response.bin").read_bytes()[80:]
    assert body.endswith(b"\x20")
    assert b"\x40" in body[:16]  # EBCDIC spaces inside the message itself


def test_logon_omits_credential_records_when_none_given() -> None:
    """Anonymous means the records are absent, not empty.

    An empty password is still a password attempt to the server, and repeated
    attempts against a real account name count towards lockout. Omitting the fields
    cannot.
    """
    from saprfclib.connection import Connection

    tlv = Connection._build_logon_request(client="001", user=None, passwd=None, seed=1)
    tags = {tag for tag, _ in _walk_tlv(tlv)}
    assert 0x0111 not in tags  # user
    assert 0x0117 not in tags  # password
    assert 0x0114 in tags  # client is still sent


def test_logon_still_carries_credentials_when_given() -> None:
    from saprfclib.connection import Connection

    tlv = Connection._build_logon_request(client="001", user="DEVELOPER", passwd="secret", seed=1)
    tags = {tag for tag, _ in _walk_tlv(tlv)}
    assert 0x0111 in tags and 0x0117 in tags


def test_partial_credentials_are_rejected() -> None:
    """One of the two missing is a mistake, not a request to go anonymous."""
    from saprfclib.connection import _resolve_credentials

    with pytest.raises(ValueError, match="passwd is missing"):
        _resolve_credentials("DEVELOPER", None, snc_lib=None, ashost="h")
    with pytest.raises(ValueError, match="user is missing"):
        _resolve_credentials(None, "secret", snc_lib=None, ashost="h")


def test_no_credentials_is_anonymous_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    """Both absent is allowed, and said out loud so it is never a silent surprise."""
    from saprfclib.connection import _resolve_credentials

    with caplog.at_level(logging.WARNING, logger="saprfclib.connection"):
        assert _resolve_credentials(None, None, snc_lib=None, ashost="h") == (None, None)
    assert any("without credentials" in r.getMessage() for r in caplog.records)


def test_snc_connections_are_left_alone() -> None:
    """SNC carries its own credentials, so the policy must not touch them."""
    from saprfclib.connection import _resolve_credentials

    assert _resolve_credentials(None, None, snc_lib="/x/libsnc.so", ashost="h") == (None, None)
    assert _resolve_credentials("U", None, snc_lib="/x/libsnc.so", ashost="h") == ("U", None)


def test_credentials_are_optional_on_both_connect_functions() -> None:
    import inspect

    from saprfclib.connection import connect, connect_async

    for fn in (connect, connect_async):
        params = inspect.signature(fn).parameters
        assert params["user"].default is None
        assert params["passwd"].default is None


# --------------------------------------------------------------------------- #
# Release-independent error decoding (kernel 7.52 vs 793)
# --------------------------------------------------------------------------- #


def test_752_signon_refusal_yields_key_and_message() -> None:
    """The 7.52 exception tags carry the same information under different numbers.

    Source: tests/golden/framing/signon_incomplete_752_response.bin. The key sits in
    0x0403 and the text in 0x0402; a reader that knows only the kernel 793 tags
    (0x0401, no free text) reports key=None and message=None while "Logon data
    incomplete." sits unread in the frame.
    """
    from saprfclib.exceptions import AbapApplicationError
    from saprfclib.invoke import raise_for_rfc_error

    body = (GOLDEN / "signon_incomplete_752_response.bin").read_bytes()[80:]
    with pytest.raises(AbapApplicationError) as excinfo:
        raise_for_rfc_error(body)
    exc = excinfo.value
    assert exc.key == "CALL_FUNCTION_SIGNON_INCOMPL"
    assert exc.message == "Logon data incomplete."
    assert (exc.msg_class, exc.msg_type, exc.msg_number) == ("00", "X", "341")
    assert exc.msg_v1 == "CALL_FUNCTION_SIGNON_INCOMPL"


def test_793_exception_tags_still_decode_after_752_support() -> None:
    """The 7.52 fallbacks must not displace the tags kernel 793 actually sends."""
    from saprfclib.exceptions import AbapApplicationError
    from saprfclib.invoke import raise_for_rfc_error

    body = (GOLDEN / "gfi_fu_not_found_response.bin").read_bytes()[80:]
    with pytest.raises(AbapApplicationError) as excinfo:
        raise_for_rfc_error(body)
    exc = excinfo.value
    assert exc.key == "FU_NOT_FOUND"
    assert (exc.msg_class, exc.msg_number) == ("FL", "046")
    assert exc.msg_v1 == "RFC_ABAP_INSTALL_AND_RUN"


def test_error_text_width_is_detected_per_value_not_assumed() -> None:
    """Error text is single-byte on 7.52 and UTF-16LE on 793 — both must decode.

    The two encodings are indistinguishable by "are all bytes < 0x80": ASCII text in
    UTF-16LE passes that test too, and decoding it as latin-1 yields "L o g o n".
    The interleaved NULs are what separates them.
    """
    from saprfclib.invoke import _decode_error_text

    assert _decode_error_text(b"Logon data incomplete.") == "Logon data incomplete."
    assert _decode_error_text("Logon data incomplete.".encode("utf-16-le")) == (
        "Logon data incomplete."
    )
    assert _decode_error_text(b"") == ""
    assert _decode_error_text(None) == ""
    # Odd length cannot be UTF-16LE, so it decodes single-byte and the trailing
    # NUL padding is stripped. The point is that it must not raise.
    assert _decode_error_text(b"\x41\x42\x00") == "AB"


def test_752_logon_response_carries_no_system_id_tags() -> None:
    """Guards the premise of the per-connection cache key.

    This release identifies itself through 0x0008/0x0006 rather than the
    0x0450/0x0452/0x0453 the 793 logon response carries. If a future capture shows
    0x0450 here after all, the cache-key fallback below is no longer needed.
    """
    body = (GOLDEN / "signon_incomplete_752_response.bin").read_bytes()[80:]
    tags = {tag for tag, _ in _walk_tlv(body)}
    assert 0x0450 not in tags
    assert 0x0452 not in tags
    assert 0x0453 not in tags
    assert 0x0008 in tags


def test_empty_response_frame_is_not_reported_as_malformed() -> None:
    """A header-only refusal has no body to be malformed.

    Observed on 7.52: an unauthenticated call is answered with the 80-byte frame
    header and nothing after it. Calling that "malformed" points the reader at the
    parser instead of at the server that sent nothing.
    """
    from saprfclib.exceptions import CommunicationError

    with pytest.raises(CommunicationError, match="empty frame") as excinfo:
        parse_invoke_response(b"", FunctionDesc(name="RFC_PING", parameters=[]))
    assert "malformed" not in str(excinfo.value)

    # A non-empty body that genuinely lacks a return code still reports as malformed.
    with pytest.raises(CommunicationError, match="malformed"):
        body = struct.pack(">HH", 0x0016, 4) + b"1101" + struct.pack(">H", 0x0016)
        parse_invoke_response(body, FunctionDesc(name="RFC_PING", parameters=[]))
