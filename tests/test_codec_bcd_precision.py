# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Packed-decimal precision and rounding.

Two facts are pinned here:

* A packed field holds up to 31 digits, more than the 28 of Python's default decimal
  context, so every digit must survive both directions exactly.
* A value with more fraction digits than the field is rounded half away from zero,
  replayed from tests/golden/serialization/bcd_rounding.json (the reference client's
  bytes for each input).
"""

from __future__ import annotations

import json
import pathlib
import time
from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib.codec import RFCTYPE_BCD, decode, encode
from saprfclib.types import FieldDesc

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "serialization" / "bcd_rounding.json").read_text(
        encoding="utf-8"
    )
)


def _field(width: int, decimals: int) -> FieldDesc:
    return FieldDesc("X", RFCTYPE_BCD, width, 0, width, 0, decimals)


FIELD = _field(FX["bytes"], FX["decimals"])


@pytest.mark.parametrize("case", FX["values"], ids=lambda c: c["input"])
def test_rounding_matches_the_reference_client_bytes(case: dict) -> None:
    raw = bytes.fromhex(case["hex"])
    assert encode(RFCTYPE_BCD, Decimal(case["input"]), FIELD) == raw
    assert decode(RFCTYPE_BCD, raw, FIELD) == Decimal(case["echo"])


@given(
    magnitude=st.integers(min_value=0, max_value=10**31 - 1),
    negative=st.booleans(),
    decimals=st.integers(min_value=0, max_value=14),
)
def test_every_digit_of_a_31_digit_field_round_trips(
    magnitude: int, negative: bool, decimals: int
) -> None:
    """P(16) holds 31 digits; nothing may be rounded to the 28-digit default context."""
    value = Decimal((1 if negative else 0, tuple(map(int, str(magnitude))), -decimals))
    field = _field(16, decimals)
    out = decode(RFCTYPE_BCD, encode(RFCTYPE_BCD, value, field), field)
    assert out == value
    assert out.as_tuple().exponent == -decimals


def test_thirty_one_digits_are_kept_exactly() -> None:
    value = Decimal("12345678901234567.89012345678901")
    field = _field(16, 14)
    assert str(decode(RFCTYPE_BCD, encode(RFCTYPE_BCD, value, field), field)) == str(value)


def test_an_oversized_exponent_is_refused_before_building_the_number() -> None:
    start = time.monotonic()
    with pytest.raises(ValueError, match="digits"):
        encode(RFCTYPE_BCD, Decimal("1E+100000000"), FIELD)
    assert time.monotonic() - start < 1.0


def test_a_tiny_exponent_rounds_to_zero_without_a_huge_divisor() -> None:
    start = time.monotonic()
    assert encode(RFCTYPE_BCD, Decimal("1E-100000000"), FIELD) == bytes(11) + b"\x0c"
    assert encode(RFCTYPE_BCD, Decimal("-1E-100000000"), FIELD) == bytes(11) + b"\x0d"
    assert time.monotonic() - start < 1.0


@pytest.mark.parametrize("text", ["NaN", "-Infinity", "Infinity", "sNaN"])
def test_specials_are_refused(text: str) -> None:
    with pytest.raises(ValueError, match="finite"):
        encode(RFCTYPE_BCD, Decimal(text), FIELD)


def test_a_value_too_wide_for_the_field_still_raises() -> None:
    with pytest.raises(ValueError, match="digits"):
        encode(RFCTYPE_BCD, Decimal("1" * 22 + ".00"), FIELD)  # 24 digits, field holds 23
