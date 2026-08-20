# tests/test_codec.py
#
# Unit tests for the saprfclib ABAP type codec (Plan 02-02, Task 1).
#
# Covers the encode/decode dispatch and every Tier-1 scalar + temporal type.
# Wire-byte expectations come from docs/protocol/serialization.md and the
# confirmed golden fixtures in tests/golden/serialization/.
#
# SAP_UC handling is verified to use explicit utf-16-le / utf-16-be only — a
# bare "utf-16" codec (which emits a BOM the wire format does not use) is a bug
# (CODEC-07 / threat T-02-05). The codec must accept bytes, bytearray, and
# memoryview inputs identically (CODEC-06).

import struct

import pytest

from saprfclib import decode, encode
from saprfclib.types import FieldDesc, TypeDesc
from tests.conftest import GOLDEN_ROOT, compare_bytes, load_fixture

SERIALIZATION_DIR = GOLDEN_ROOT / "serialization"


def _scalar_field(rfctype: int, *, uc_length: int = 0, unicode_mode: bool = True) -> FieldDesc:
    """A minimal scalar FieldDesc for codec tests.

    uc_length is the Unicode wire byte length (2 * char count for SAP_UC types).
    """
    return FieldDesc(
        name="F",
        rfctype=rfctype,
        nuc_length=uc_length // 2 if uc_length else 0,
        nuc_offset=0,
        uc_length=uc_length,
        uc_offset=0,
        decimals=0,
        unicode_mode=unicode_mode,
    )


# RFCTYPE integer constants mirrored from the codec / serialization.md.
CHAR, DATE, BCD, TIME, BYTE, TABLE, NUM, FLOAT, INT = 0, 1, 2, 3, 4, 5, 6, 7, 8
INT2, INT1, STRUCTURE = 9, 10, 17
DECF16, DECF34, STRING, XSTRING, INT8 = 23, 24, 29, 30, 31
UTCLONG, UTCSECOND, UTCMINUTE = 32, 33, 34
DTDAY, DTWEEK, DTMONTH, TSECOND, TMINUTE, CDAY = 35, 36, 37, 38, 39, 40


# --------------------------------------------------------------------------- #
# Integer scalars
# --------------------------------------------------------------------------- #


def test_int4_decode_le():
    f = _scalar_field(INT)
    assert decode(INT, b"\x00\x00\x01\x00", f) == 65536


def test_int4_roundtrip():
    f = _scalar_field(INT)
    assert encode(INT, 65536, f) == b"\x00\x00\x01\x00"
    assert decode(INT, encode(INT, -5, f), f) == -5


def test_int2_decode_signed_le():
    f = _scalar_field(INT2)
    # 0x00 0x01 LE = 256 (matches type_int2 fixture)
    assert decode(INT2, b"\x00\x01", f) == 256
    assert decode(INT2, encode(INT2, -1, f), f) == -1


def test_int1_unsigned():
    f = _scalar_field(INT1)
    assert decode(INT1, b"\x05", f) == 5
    assert encode(INT1, 42, f) == b"\x2a"
    assert decode(INT1, b"\xff", f) == 255  # unsigned


def test_int8_roundtrip():
    f = _scalar_field(INT8)
    assert decode(INT8, b"\x2a\x00\x00\x00\x00\x00\x00\x00", f) == 42
    assert decode(INT8, encode(INT8, -123456789, f), f) == -123456789


def test_float_roundtrip():
    f = _scalar_field(FLOAT)
    wire = struct.pack("<d", 3.14159)
    assert decode(FLOAT, wire, f) == 3.14159
    assert isinstance(decode(FLOAT, wire, f), float)
    assert encode(FLOAT, 3.14159, f) == wire


# --------------------------------------------------------------------------- #
# SAP_UC fixed-width: CHAR / NUM / DATE / TIME
# --------------------------------------------------------------------------- #


def test_char_decode_strips_trailing_spaces():
    f = _scalar_field(CHAR, uc_length=8)  # CHAR(4)
    wire = "A   ".encode("utf-16-le")
    assert decode(CHAR, wire, f) == "A"


def test_char_encode_pads_to_width_off_by_2x():
    f = _scalar_field(CHAR, uc_length=8)  # CHAR(4) => 8 wire bytes
    wire = encode(CHAR, "AB", f)
    assert len(wire) == 8  # off-by-2x respected
    assert wire == "AB  ".encode("utf-16-le")


def test_char_roundtrip():
    f = _scalar_field(CHAR, uc_length=8)
    assert decode(CHAR, encode(CHAR, "ABCD", f), f) == "ABCD"


def test_date_decode_returns_str_not_datetime():
    f = _scalar_field(DATE, uc_length=16)
    wire = "20260626".encode("utf-16-le")
    result = decode(DATE, wire, f)
    assert result == "20260626"
    assert isinstance(result, str)  # D-13: DATE stays str, not datetime


def test_time_decode_returns_str():
    f = _scalar_field(TIME, uc_length=12)
    wire = "120000".encode("utf-16-le")
    result = decode(TIME, wire, f)
    assert result == "120000"
    assert isinstance(result, str)


def test_num_zero_padded():
    f = _scalar_field(NUM, uc_length=8)  # NUM(4)
    wire = encode(NUM, "42", f)
    assert wire == "0042".encode("utf-16-le")
    assert decode(NUM, wire, f) == "0042"


def test_char_explicit_utf16_be_when_non_unicode():
    f = _scalar_field(CHAR, uc_length=8, unicode_mode=False)
    f.nuc_length = 4
    wire = encode(CHAR, "AB", f)
    # non-unicode path uses utf-16-be (NEVER bare utf-16)
    assert wire == "AB  ".encode("utf-16-be")
    assert decode(CHAR, wire, f) == "AB"


# --------------------------------------------------------------------------- #
# Variable-length: STRING / XSTRING and fixed BYTE
# --------------------------------------------------------------------------- #


def test_string_roundtrip():
    f = _scalar_field(STRING)
    wire = encode(STRING, "Hello", f)
    # STRING wire = UTF-8 bytes, no internal length prefix (GAP-B-06 closed)
    assert wire == b"Hello"
    assert decode(STRING, wire, f) == "Hello"


def test_xstring_roundtrip():
    f = _scalar_field(XSTRING)
    raw = b"\xde\xad\xbe\xef"
    wire = encode(XSTRING, raw, f)
    # XSTRING wire = raw bytes, no internal length prefix (GAP-B-06 closed)
    assert wire == raw
    assert decode(XSTRING, wire, f) == raw
    assert isinstance(decode(XSTRING, wire, f), bytes)


def test_byte_decode_returns_bytes():
    f = _scalar_field(BYTE)
    f.uc_length = 4
    f.nuc_length = 4
    raw = b"\xde\xad\xbe\xef"
    assert decode(BYTE, raw, f) == raw
    assert isinstance(decode(BYTE, raw, f), bytes)
    assert encode(BYTE, raw, f) == raw


# --------------------------------------------------------------------------- #
# Temporal extension types
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "rfctype,size",
    [
        (UTCLONG, 8),
        (UTCSECOND, 8),
        (UTCMINUTE, 8),
        (DTDAY, 4),
        (DTWEEK, 4),
        (DTMONTH, 4),
        (TSECOND, 4),
        (TMINUTE, 2),
        (CDAY, 2),
    ],
)
def test_temporal_roundtrip(rfctype, size):
    f = _scalar_field(rfctype)
    wire = encode(rfctype, 42, f)
    assert len(wire) == size
    assert decode(rfctype, wire, f) == 42
    assert isinstance(decode(rfctype, wire, f), int)


# --------------------------------------------------------------------------- #
# Buffer polymorphism (CODEC-06): bytes / bytearray / memoryview
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("ctor", [bytes, bytearray, memoryview])
def test_decode_accepts_all_buffer_types_int(ctor):
    f = _scalar_field(INT)
    data = ctor(b"\x00\x00\x01\x00")
    assert decode(INT, data, f) == 65536


@pytest.mark.parametrize("ctor", [bytes, bytearray, memoryview])
def test_decode_accepts_all_buffer_types_char(ctor):
    f = _scalar_field(CHAR, uc_length=8)
    data = ctor("ABCD".encode("utf-16-le"))
    assert decode(CHAR, data, f) == "ABCD"


@pytest.mark.parametrize("ctor", [bytes, bytearray, memoryview])
def test_decode_accepts_all_buffer_types_string(ctor):
    f = _scalar_field(STRING)
    base = b"Hello"
    assert decode(STRING, ctor(base), f) == "Hello"


# --------------------------------------------------------------------------- #
# Error handling: out-of-scope, not-yet-implemented, over-read
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rfctype", [14, 16, 28])
def test_out_of_scope_types_raise_valueerror(rfctype):
    f = _scalar_field(rfctype)
    with pytest.raises(ValueError):
        decode(rfctype, b"", f)
    with pytest.raises(ValueError):
        encode(rfctype, None, f)


@pytest.mark.parametrize("rfctype", [DECF16, DECF34])
def test_decfloat_raises_notimplemented(rfctype):
    """DecFloat16/34 ship a documented NotImplementedError gap.

    No reachable DECFLOAT-typed function module existed on the test system, so
    the wire form is unconfirmed. Per the no-guessing constraint the codec
    raises rather than guessing a DPD implementation. This is an intended
    outcome, not a failure — see type_decf16_GAP.json.

    The message must name the type and say it is unimplemented: a user hitting
    this needs to know why, not an internal tracker id.
    """
    f = _scalar_field(rfctype)
    with pytest.raises(NotImplementedError) as dec_exc:
        decode(rfctype, b"\x00" * 8, f)
    assert "DECF" in str(dec_exc.value) and "not implemented" in str(dec_exc.value)
    with pytest.raises(NotImplementedError) as enc_exc:
        encode(rfctype, None, f)
    assert "DECF" in str(enc_exc.value) and "not implemented" in str(enc_exc.value)


def test_decfloat_gap_marker_fixture_documents_intentional_gap():
    """type_decf16_GAP.json records GAP-B-01 as an intentional, no-guess gap.

    The marker has no .bin pair (so the fixture runner skips it) and names both
    DecFloat RFCTYPE ids — confirming the deferral is documented, not hidden.
    """
    import json

    marker = json.loads((SERIALIZATION_DIR / "type_decf16_GAP.json").read_text())
    assert marker["gap_id"] == "GAP-B-01"
    assert marker["rfctype"]["RFCTYPE_DECF16"] == DECF16
    assert marker["rfctype"]["RFCTYPE_DECF34"] == DECF34
    assert not (SERIALIZATION_DIR / "type_decf16_GAP.bin").exists()


def test_bcd_decode_returns_decimal():
    """BCD decodes to decimal.Decimal (CODEC-02) — sanity smoke at unit level."""
    from decimal import Decimal

    f = _scalar_field(BCD)
    f.uc_length = 3
    f.nuc_length = 3
    f.decimals = 2
    result = decode(BCD, bytes.fromhex("12345C"), f)
    assert result == Decimal("123.45")
    assert isinstance(result, Decimal)


def test_string_invalid_utf8_raises():
    f = _scalar_field(STRING)
    # Invalid UTF-8 sequence — must raise rather than silently corrupt (T-02-03).
    with pytest.raises((UnicodeDecodeError, ValueError)):
        decode(STRING, b"\xff\xfe", f)


def test_no_bare_utf16_in_codec_source():
    """Guard: codec.py must never use a bare 'utf-16' codec (BOM corruption)."""
    import pathlib

    import saprfclib.codec as codec_mod

    src = pathlib.Path(codec_mod.__file__).read_text()
    for line in src.splitlines():
        if "utf-16" in line and "-le" not in line and "-be" not in line:
            raise AssertionError(f"bare utf-16 found: {line!r}")


# --------------------------------------------------------------------------- #
# STRUCTURE / TABLE (Plan 02-03) — descriptor-driven, arbitrary-depth recursion
# --------------------------------------------------------------------------- #


def _char4_int4_type_desc(*, unicode_mode: bool = True) -> TypeDesc:
    """A CHAR(4)+INT4 row layout matching type_structure/type_table fixtures.

    Field offsets are *row-relative* (the codec lays a TABLE row at its own
    base). uc layout: CHAR(4)=8 bytes @0, INT4=4 bytes @8 → uc_size 12.
    nuc layout: CHAR(4)=4 bytes @0, INT4=4 bytes @4 → nuc_size 8.
    """
    char_f = FieldDesc(
        name="RFCCHAR4",
        rfctype=CHAR,
        nuc_length=4,
        nuc_offset=0,
        uc_length=8,
        uc_offset=0,
        decimals=0,
        unicode_mode=unicode_mode,
    )
    int_f = FieldDesc(
        name="RFCINT4",
        rfctype=INT,
        nuc_length=4,
        nuc_offset=4,
        uc_length=4,
        uc_offset=8,
        decimals=0,
        unicode_mode=unicode_mode,
    )
    return TypeDesc(name="CHAR4_INT4", fields=[char_f, int_f], nuc_size=8, uc_size=12)


def _struct_field(td: TypeDesc, *, unicode_mode: bool = True) -> FieldDesc:
    return FieldDesc(
        name="STRUCT",
        rfctype=STRUCTURE,
        nuc_length=td.nuc_size,
        nuc_offset=0,
        uc_length=td.uc_size,
        uc_offset=0,
        decimals=0,
        unicode_mode=unicode_mode,
        type_desc=td,
    )


def _table_field(td: TypeDesc, *, unicode_mode: bool = True) -> FieldDesc:
    return FieldDesc(
        name="TABLE",
        rfctype=TABLE,
        nuc_length=td.nuc_size,
        nuc_offset=0,
        uc_length=td.uc_size,
        uc_offset=0,
        decimals=0,
        unicode_mode=unicode_mode,
        type_desc=td,
    )


def test_structure_decode_returns_dict():
    td = _char4_int4_type_desc()
    f = _struct_field(td)
    wire = bytes.fromhex("4100420043004400") + b"\x00\x00\x01\x00"
    result = decode(STRUCTURE, wire, f)
    assert isinstance(result, dict)
    assert result == {"RFCCHAR4": "ABCD", "RFCINT4": 65536}


def test_structure_roundtrip():
    td = _char4_int4_type_desc()
    f = _struct_field(td)
    wire = bytes.fromhex("4100420043004400") + b"\x00\x00\x01\x00"
    assert encode(STRUCTURE, decode(STRUCTURE, wire, f), f) == wire


def test_structure_nuc_offsets_selected_when_non_unicode():
    """unicode_mode=False must read fields at nuc offsets (CODEC-04)."""
    td = _char4_int4_type_desc(unicode_mode=False)
    f = _struct_field(td, unicode_mode=False)
    # nuc layout: CHAR(4) UTF-16-BE @0 (8 bytes) + INT4 @4 (4 bytes) → 8 bytes total
    # but nuc CHAR is half-width: 4 bytes for 4 chars is impossible in UTF-16.
    # nuc_size=8 means CHAR occupies bytes 0..4 (BE, 2 chars worth) — use a
    # 2-char CHAR for the nuc case to keep widths honest.
    char_f = td.fields[0]
    char_f.nuc_length = 4  # 2 UTF-16-BE chars
    int_f = td.fields[1]
    int_f.nuc_offset = 4
    wire = "AB".encode("utf-16-be") + b"\x00\x00\x01\x00"
    result = decode(STRUCTURE, wire, f)
    assert result == {"RFCCHAR4": "AB", "RFCINT4": 65536}


def test_table_decode_returns_list_of_dicts():
    td = _char4_int4_type_desc()
    f = _table_field(td)
    row = bytes.fromhex("4100420043004400") + b"\x00\x00\x01\x00"
    wire = row + row
    result = decode(TABLE, wire, f)
    assert isinstance(result, list)
    assert len(result) == 2
    assert all(isinstance(r, dict) for r in result)
    assert result == [
        {"RFCCHAR4": "ABCD", "RFCINT4": 65536},
        {"RFCCHAR4": "ABCD", "RFCINT4": 65536},
    ]


def test_table_roundtrip():
    td = _char4_int4_type_desc()
    f = _table_field(td)
    row = bytes.fromhex("4100420043004400") + b"\x00\x00\x01\x00"
    wire = row + row
    assert encode(TABLE, decode(TABLE, wire, f), f) == wire


def test_nested_table_in_structure_in_table_arbitrary_depth():
    """TABLE → STRUCTURE → TABLE round-trips with no depth limit (D-08, CODEC-05)."""
    # Inner table row: a single INT4 (uc_size 4).
    inner_int = FieldDesc(
        name="N",
        rfctype=INT,
        nuc_length=4,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
    )
    inner_td = TypeDesc(name="INNER", fields=[inner_int], nuc_size=4, uc_size=4)

    # Middle structure: one INT4 + one TABLE<inner>. The TABLE field is
    # variable-length, so the middle structure here holds exactly one inner row
    # (uc_size = 4 for the INT4 + 4 for one inner row = 8).
    mid_int = FieldDesc(
        name="M",
        rfctype=INT,
        nuc_length=4,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
    )
    mid_table = FieldDesc(
        name="INNER_T",
        rfctype=TABLE,
        nuc_length=4,
        nuc_offset=4,
        uc_length=4,
        uc_offset=4,
        decimals=0,
        type_desc=inner_td,
    )
    mid_td = TypeDesc(name="MID", fields=[mid_int, mid_table], nuc_size=8, uc_size=8)

    outer_field = _table_field(mid_td)

    value = [
        {"M": 1, "INNER_T": [{"N": 10}]},
        {"M": 2, "INNER_T": [{"N": 20}]},
    ]
    wire = encode(TABLE, value, outer_field)
    decoded = decode(TABLE, wire, outer_field)
    assert decoded == value


def test_structure_field_span_past_buffer_raises_typed_error():
    """A field span exceeding the buffer raises a typed decode error (T-02-07)."""
    td = _char4_int4_type_desc()
    f = _struct_field(td)
    # INT4 field needs bytes [8:12] but buffer is only 10 bytes long.
    truncated = bytes.fromhex("4100420043004400") + b"\x00\x00"
    with pytest.raises(ValueError):
        decode(STRUCTURE, truncated, f)


# --------------------------------------------------------------------------- #
# Fixture replay (Task 2): type_structure / type_table golden fixtures
# --------------------------------------------------------------------------- #


def test_type_structure_fixture_replay():
    fix = load_fixture(SERIALIZATION_DIR, "type_structure")
    td = _char4_int4_type_desc()
    f = _struct_field(td)
    decoded = decode(STRUCTURE, fix.payload_bytes, f)
    assert decoded == {"RFCCHAR4": "ABCD", "RFCINT4": 65536}
    re_encoded = encode(STRUCTURE, decoded, f)
    assert compare_bytes(re_encoded, fix.payload_bytes, fix.field_annotations) == []


def test_type_structure_fixture_nuc_path():
    """Same fixture members, decoded via the nuc offset path (CODEC-04)."""
    # The .bin is the UNICODE wire layout; here we assert the codec *selects*
    # nuc offsets when unicode_mode=False by decoding a hand-built nuc buffer.
    td = _char4_int4_type_desc(unicode_mode=False)
    td.fields[0].nuc_length = 8  # CHAR(4) in UTF-16-BE = 8 bytes
    td.fields[1].nuc_offset = 8
    td.nuc_size = 12
    f = _struct_field(td, unicode_mode=False)
    f.nuc_length = 12
    nuc_wire = "ABCD".encode("utf-16-be") + b"\x00\x00\x01\x00"
    assert decode(STRUCTURE, nuc_wire, f) == {"RFCCHAR4": "ABCD", "RFCINT4": 65536}


def test_type_table_fixture_replay():
    fix = load_fixture(SERIALIZATION_DIR, "type_table")
    td = _char4_int4_type_desc()
    f = _table_field(td)
    decoded = decode(TABLE, fix.payload_bytes, f)
    assert isinstance(decoded, list)
    assert decoded == [
        {"RFCCHAR4": "ABCD", "RFCINT4": 65536},
        {"RFCCHAR4": "ABCD", "RFCINT4": 65536},
    ]
    assert len(decoded) == fix.expected_parse["row_count"]
    re_encoded = encode(TABLE, decoded, f)
    assert compare_bytes(re_encoded, fix.payload_bytes, fix.field_annotations) == []
