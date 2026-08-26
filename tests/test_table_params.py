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

    with pytest.raises(CommunicationError, match="no return-code TLV"):
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
