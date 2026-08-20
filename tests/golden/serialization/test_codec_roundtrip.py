# tests/golden/serialization/test_codec_roundtrip.py
#
# Hypothesis property-based round-trip tests for the saprfclib codec (D-12).
#
# These supplement the golden-fixture replay: fixtures pin the exact wire bytes
# for known values, while these properties prove decode(encode(value)) == value
# across each type's full domain — the asymmetry/corruption guard (threat
# T-02-04).
#
# SAP_UC round-trips run under BOTH unicode_mode=True (utf-16-le) and
# unicode_mode=False (utf-16-be) so both byte orders are covered (CODEC-07).
# A bare BOM-bearing UTF-16 codec is never used (only -le / -be). The st.text
# strategy includes supplementary-plane code points (emoji) to catch
# surrogate-pair bugs.
#
# Test naming follows the VALIDATION map: SAP_UC tests match `-k utf16` and
# `-k sap_uc`; temporal tests match `-k temporal`.

from __future__ import annotations

import math
from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib import decode, encode
from saprfclib.types import FieldDesc
from tests.conftest import GOLDEN_ROOT, compare_bytes, load_fixture

SERIALIZATION_DIR = GOLDEN_ROOT / "serialization"

# RFCTYPE constants used here.
CHAR, BCD, NUM, FLOAT, INT = 0, 2, 6, 7, 8
INT2, INT1 = 9, 10
STRING, XSTRING, INT8 = 29, 30, 31
UTCLONG, UTCSECOND, UTCMINUTE = 32, 33, 34
DTDAY, DTWEEK, DTMONTH, TSECOND, TMINUTE, CDAY = 35, 36, 37, 38, 39, 40


def _field(rfctype: int, *, uc_length: int = 0, unicode_mode: bool = True) -> FieldDesc:
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


def _bcd_field(*, precision: int, decimals: int) -> FieldDesc:
    """A BCD FieldDesc.

    BCD uses ``decimals`` for the decimal scale and ``uc_length``/``nuc_length``
    as the on-wire byte width: ceil((precision + 1) / 2) bytes (digits + sign
    nibble, 2 nibbles per byte). The digit count is derived from the byte width
    by the codec (width * 2 - 1), so no separate precision attribute is needed.
    """
    width = math.ceil((precision + 1) / 2)
    return FieldDesc(
        name="P",
        rfctype=BCD,
        nuc_length=width,
        nuc_offset=0,
        uc_length=width,
        uc_offset=0,
        decimals=decimals,
        unicode_mode=True,
    )


# Signed/unsigned bounds per integer width.
_INT_RANGES: dict[int, tuple[int, int]] = {
    INT1: (0, 0xFF),  # unsigned 8-bit
    INT2: (-(2**15), 2**15 - 1),  # signed 16-bit
    INT: (-(2**31), 2**31 - 1),  # signed 32-bit
    INT8: (-(2**63), 2**63 - 1),  # signed 64-bit
}

# Temporal types share the integer wire format of a matching width.
_TEMPORAL_RANGES: dict[int, tuple[int, int]] = {
    UTCLONG: (-(2**63), 2**63 - 1),
    UTCSECOND: (-(2**63), 2**63 - 1),
    UTCMINUTE: (-(2**63), 2**63 - 1),
    DTDAY: (-(2**31), 2**31 - 1),
    DTWEEK: (-(2**31), 2**31 - 1),
    DTMONTH: (-(2**31), 2**31 - 1),
    TSECOND: (-(2**31), 2**31 - 1),
    TMINUTE: (-(2**15), 2**15 - 1),
    CDAY: (-(2**15), 2**15 - 1),
}


# --------------------------------------------------------------------------- #
# Integer scalars
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rfctype", list(_INT_RANGES))
def test_int_roundtrip(rfctype):
    lo, hi = _INT_RANGES[rfctype]
    f = _field(rfctype)

    @given(st.integers(min_value=lo, max_value=hi))
    def check(value):
        assert decode(rfctype, encode(rfctype, value, f), f) == value

    check()


# --------------------------------------------------------------------------- #
# Temporal extension types (selectable via -k temporal)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rfctype", list(_TEMPORAL_RANGES))
def test_temporal_roundtrip(rfctype):
    lo, hi = _TEMPORAL_RANGES[rfctype]
    f = _field(rfctype)

    @given(st.integers(min_value=lo, max_value=hi))
    def check(value):
        assert decode(rfctype, encode(rfctype, value, f), f) == value

    check()


# --------------------------------------------------------------------------- #
# FLOAT
# --------------------------------------------------------------------------- #


@given(st.floats(allow_nan=False, allow_infinity=False))
def test_float_roundtrip(value):
    f = _field(FLOAT)
    result = decode(FLOAT, encode(FLOAT, value, f), f)
    # exact bit-for-bit round-trip for finite doubles
    assert result == value or (value == 0.0 and result == 0.0)


# --------------------------------------------------------------------------- #
# SAP_UC: CHAR (fixed) and STRING (variable) under utf-16-le AND utf-16-be
# (selectable via -k utf16 / -k sap_uc)
# --------------------------------------------------------------------------- #

# A text strategy that includes supplementary-plane code points (emoji) to
# exercise surrogate-pair handling. Exclude the pad characters and surrogate
# code units so fixed-width padding round-trips cleanly.
_UC_TEXT = st.text(
    alphabet=st.characters(
        min_codepoint=0x21,
        max_codepoint=0x10FFFF,
        blacklist_categories=("Cs",),  # no lone surrogates
    ),
    max_size=8,
)


@pytest.mark.parametrize("unicode_mode", [True, False])
def test_sap_uc_char_roundtrip_utf16(unicode_mode):
    """CHAR round-trips under both utf-16-le and utf-16-be (CODEC-07)."""
    char_width = 8
    f = _field(CHAR, uc_length=char_width * 2, unicode_mode=unicode_mode)

    @given(_UC_TEXT)
    def check(text):
        # Fit to the field width; CHAR right-pads with spaces and rstrips them,
        # so a trailing-space-free value of the right length round-trips.
        fitted = text[:char_width].rstrip(" ")
        result = decode(CHAR, encode(CHAR, fitted, f), f)
        assert result == fitted

    check()


def test_string_roundtrip_utf8():
    """Variable-length STRING round-trips via UTF-8 (SAP codepage 4110, GAP-B-06)."""
    f = _field(STRING)

    @given(_UC_TEXT)
    def check(text):
        assert decode(STRING, encode(STRING, text, f), f) == text

    check()


# --------------------------------------------------------------------------- #
# XSTRING / BYTE: raw bytes
# --------------------------------------------------------------------------- #


@given(st.binary(max_size=64))
def test_xstring_roundtrip(raw):
    f = _field(XSTRING)
    assert decode(XSTRING, encode(XSTRING, raw, f), f) == raw


# --------------------------------------------------------------------------- #
# BCD packed decimals (CODEC-02) — decimal.Decimal only, never float.
# Selectable via -k bcd. Confirmed wire form from the live BAPISFLIGHT.PRICE
# capture (type_bcd_p15_2): 2 digits/byte, sign nibble in the low nibble of the
# last byte, 0x0C=positive / 0x0D=negative (SDK type definitions SAP_BCD).
# --------------------------------------------------------------------------- #


def test_bcd_decode_live_p15_2_fixture():
    """The live-captured P15.2 fixture decodes to 800000.50 (byte-for-byte)."""
    fix = load_fixture(SERIALIZATION_DIR, "type_bcd_p15_2")
    f = _bcd_field(precision=15, decimals=2)
    result = decode(BCD, fix.payload_bytes, f)
    assert result == Decimal("800000.50")
    assert isinstance(result, Decimal)


def test_bcd_replay_live_p15_2_fixture_byte_for_byte():
    """decode → encode reproduces the exact live wire bytes (no float anywhere)."""
    fix = load_fixture(SERIALIZATION_DIR, "type_bcd_p15_2")
    f = _bcd_field(precision=15, decimals=2)
    decoded = decode(BCD, fix.payload_bytes, f)
    re_encoded = encode(BCD, decoded, f)
    assert compare_bytes(re_encoded, fix.payload_bytes, fix.field_annotations) == []
    assert re_encoded == bytes.fromhex("000000080000050C")


def test_bcd_replay_type_bcd_fixture_byte_for_byte():
    """The P5.2 type_bcd fixture round-trips byte-for-byte (01 23 4C)."""
    fix = load_fixture(SERIALIZATION_DIR, "type_bcd")
    f = _bcd_field(precision=5, decimals=2)
    decoded = decode(BCD, fix.payload_bytes, f)
    re_encoded = encode(BCD, decoded, f)
    assert re_encoded == fix.payload_bytes
    assert isinstance(decoded, Decimal)


def test_bcd_decode_returns_decimal_never_float():
    f = _bcd_field(precision=5, decimals=2)
    result = decode(BCD, bytes.fromhex("12345C"), f)
    assert isinstance(result, Decimal)
    assert not isinstance(result, float)
    assert result == Decimal("123.45")


@pytest.mark.parametrize(
    "sign_nibble,negative",
    [
        (0x0C, False),  # canonical positive
        (0x0F, False),  # alternate positive (unsigned)
        (0x0B, False),  # alternate positive
        (0x0D, True),  # canonical negative
    ],
)
def test_bcd_decode_accepts_all_four_sign_nibbles(sign_nibble, negative):
    """0x0C/0x0F/0x0B → positive, 0x0D → negative on decode (Pitfall 4)."""
    f = _bcd_field(precision=5, decimals=2)
    # digits 12345, sign nibble varies in the low nibble of the last byte.
    wire = bytes([0x12, 0x34, (0x5 << 4) | sign_nibble])
    result = decode(BCD, wire, f)
    expected = Decimal("-123.45") if negative else Decimal("123.45")
    assert result == expected


def test_bcd_encode_emits_only_canonical_sign_nibbles():
    """encode must emit 0x0C for non-negative and 0x0D for negative only."""
    f = _bcd_field(precision=5, decimals=2)
    pos = encode(BCD, Decimal("123.45"), f)
    neg = encode(BCD, Decimal("-123.45"), f)
    assert pos[-1] & 0x0F == 0x0C
    assert neg[-1] & 0x0F == 0x0D
    assert pos == bytes.fromhex("12345C")
    assert neg == bytes.fromhex("12345D")


def test_bcd_initial_zero_form_roundtrips():
    """The initial/zero form (Decimal('0')) round-trips to a positive zero."""
    f = _bcd_field(precision=15, decimals=2)
    wire = encode(BCD, Decimal("0"), f)
    # all-zero digits + positive sign 0x0C in the final low nibble.
    assert wire == bytes.fromhex("000000000000000C")
    assert decode(BCD, wire, f) == Decimal("0.00")


def test_bcd_odd_and_even_digit_counts_roundtrip():
    """Odd (precision 5) and even (precision 4) digit counts both round-trip."""
    odd = _bcd_field(precision=5, decimals=2)  # 5 digits → 3 bytes
    even = _bcd_field(precision=4, decimals=2)  # ... ceil((4+1)/2)=3 bytes too
    assert decode(BCD, encode(BCD, Decimal("123.45"), odd), odd) == Decimal("123.45")
    assert decode(BCD, encode(BCD, Decimal("12.34"), even), even) == Decimal("12.34")


def test_bcd_max_decimals_roundtrips_without_precision_loss():
    """A value scaled to the full decimals round-trips exactly via Decimal."""
    f = _bcd_field(precision=15, decimals=6)
    value = Decimal("123456.789012")
    assert decode(BCD, encode(BCD, value, f), f) == value


@given(st.integers(min_value=-(10**12) + 1, max_value=10**12 - 1))
def test_bcd_roundtrip_property_p15_2(unscaled):
    """decode(encode(value)) == value for arbitrary P15.2 Decimals (Hypothesis)."""
    f = _bcd_field(precision=15, decimals=2)
    value = Decimal(unscaled).scaleb(-2)
    assert decode(BCD, encode(BCD, value, f), f) == value
