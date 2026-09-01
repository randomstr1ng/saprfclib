# SPDX-License-Identifier: MPL-2.0
"""Codec guard paths.

`codec.py` is where a defect corrupts data rather than failing: a wrong decimal
is delivered to the caller as a number, not an error. These are its refusal
branches — the ones that stop a malformed field being silently interpreted.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from saprfclib.codec import (
    RFCTYPE_BCD,
    RFCTYPE_CHAR,
    RFCTYPE_INT1,
    RFCTYPE_TABLE,
    decode,
    encode,
)
from saprfclib.types import FieldDesc, TypeDesc


def _field(rfctype: int, *, nuc: int = 8, uc: int = 16, decimals: int = 0) -> FieldDesc:
    return FieldDesc(
        name="F",
        rfctype=rfctype,
        nuc_length=nuc,
        nuc_offset=0,
        uc_length=uc,
        uc_offset=0,
        decimals=decimals,
    )


# --------------------------------------------------------------------------- #
# BCD — the type that carries money
# --------------------------------------------------------------------------- #


def test_bcd_refuses_a_float() -> None:
    """Binary float cannot hold a base-10 decimal exactly.

    Accepting one would round silently, which is the exact failure BCD exists to
    prevent — and it would look like a working call.
    """
    with pytest.raises((TypeError, ValueError)):
        encode(RFCTYPE_BCD, 1.15, _field(RFCTYPE_BCD, decimals=2))


def test_bcd_accepts_the_exact_types() -> None:
    for value in (Decimal("1.15"), 1, "1.15"):
        raw = encode(RFCTYPE_BCD, value, _field(RFCTYPE_BCD, decimals=2))
        assert isinstance(raw, (bytes, bytearray))


def test_bcd_round_trips_a_value_float_cannot_represent() -> None:
    field = _field(RFCTYPE_BCD, decimals=2)
    value = Decimal("1.15")
    assert decode(RFCTYPE_BCD, encode(RFCTYPE_BCD, value, field), field) == value
    assert decode(RFCTYPE_BCD, encode(RFCTYPE_BCD, value, field), field) != Decimal(1.15)


def test_a_zero_width_bcd_field_is_refused() -> None:
    """Width comes from server metadata; zero would silently yield nothing."""
    zero = _field(RFCTYPE_BCD, nuc=0, uc=0)
    with pytest.raises(ValueError, match="width must be positive"):
        decode(RFCTYPE_BCD, b"", zero)
    with pytest.raises(ValueError, match="width must be positive"):
        encode(RFCTYPE_BCD, Decimal(1), zero)


def test_a_truncated_bcd_field_is_refused() -> None:
    """Fewer bytes than the declared width cannot be decoded, only guessed at."""
    field = _field(RFCTYPE_BCD, nuc=8, uc=8, decimals=2)
    with pytest.raises(ValueError, match="truncated"):
        decode(RFCTYPE_BCD, b"\x00\x00", field)


def test_an_invalid_bcd_sign_nibble_is_refused() -> None:
    """0xC/0xD/0xF are the valid signs; anything else is not a packed decimal.

    Guessing a sign here would flip the sign of a financial value without a word.
    """
    field = _field(RFCTYPE_BCD, nuc=4, uc=4, decimals=2)
    with pytest.raises(ValueError, match="sign nibble"):
        decode(RFCTYPE_BCD, b"\x00\x00\x01\x2a", field)
    # 0xC, 0xD and 0xF are valid and must still decode.
    # 4 bytes is 8 nibbles: 7 digit positions plus the sign, so 0000012 at
    # 2 decimals is 0.12.
    assert decode(RFCTYPE_BCD, b"\x00\x00\x01\x2c", field) == Decimal("0.12")
    assert decode(RFCTYPE_BCD, b"\x00\x00\x01\x2d", field) == Decimal("-0.12")


def test_an_invalid_bcd_digit_nibble_is_refused() -> None:
    """A nibble above 9 is not a decimal digit; reading it as one invents a value."""
    field = _field(RFCTYPE_BCD, nuc=4, uc=4, decimals=2)
    with pytest.raises(ValueError, match="digit nibble"):
        decode(RFCTYPE_BCD, b"\x00\x00\xa1\x2c", field)


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #


def test_int1_range_is_enforced() -> None:
    """A wrapped byte is a different number, delivered as if it were the caller's."""
    field = _field(RFCTYPE_INT1, nuc=1, uc=1)
    assert decode(RFCTYPE_INT1, encode(RFCTYPE_INT1, 255, field), field) == 255
    for bad in (256, -1, 1000):
        with pytest.raises(ValueError, match="INT1 out of range"):
            encode(RFCTYPE_INT1, bad, field)


def test_a_zero_row_size_table_is_refused() -> None:
    """Row size comes from the server; zero would loop forever or yield nothing."""
    row = TypeDesc(name="R", fields=[], nuc_size=0, uc_size=0)
    field = FieldDesc(
        name="T",
        rfctype=RFCTYPE_TABLE,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        type_desc=row,
    )
    with pytest.raises(ValueError, match="row size must be positive"):
        decode(RFCTYPE_TABLE, b"abcd", field)


def test_char_encoding_pads_and_truncates_to_the_field() -> None:
    """Fixed width in both directions — the recurring defect class in this codebase."""
    field = _field(RFCTYPE_CHAR, nuc=4, uc=8)
    for value in ("", "ab", "abcd", "abcdefgh"):
        assert len(encode(RFCTYPE_CHAR, value, field)) == 8


def test_char_decode_strips_the_blank_padding() -> None:
    field = _field(RFCTYPE_CHAR, nuc=4, uc=8)
    assert decode(RFCTYPE_CHAR, encode(RFCTYPE_CHAR, "ab", field), field) == "ab"
