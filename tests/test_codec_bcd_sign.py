# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Packed-decimal sign nibbles, replayed from tests/golden/serialization/bcd_sign.json."""

from __future__ import annotations

import json
import pathlib
from decimal import Decimal

import pytest

from saprfclib.codec import RFCTYPE_BCD, decode, encode
from saprfclib.types import FieldDesc

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "serialization" / "bcd_sign.json").read_text(
        encoding="utf-8"
    )
)
FIELD = FieldDesc(
    name="X",
    rfctype=RFCTYPE_BCD,
    nuc_length=FX["bytes"],
    nuc_offset=0,
    uc_length=FX["bytes"],
    uc_offset=0,
    decimals=FX["decimals"],
)


@pytest.mark.parametrize("case", FX["values"], ids=lambda c: c["value"])
def test_packed_decimal_matches_the_capture(case: dict) -> None:
    raw = bytes.fromhex(case["hex"])
    assert decode(RFCTYPE_BCD, raw, FIELD) == Decimal(case["value"])
    assert encode(RFCTYPE_BCD, Decimal(case["value"]), FIELD) == raw


def test_sign_nibbles() -> None:
    signs = {Decimal(c["value"]) < 0: bytes.fromhex(c["hex"])[-1] & 0x0F for c in FX["values"]}
    assert signs == {True: 0x0D, False: 0x0C}
