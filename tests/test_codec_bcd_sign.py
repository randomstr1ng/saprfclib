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


# --------------------------------------------------------------------------- #
# Every sign nibble a peer can send (#70, #69)
# --------------------------------------------------------------------------- #

NIBBLES = json.loads(
    (
        pathlib.Path(__file__).parent / "golden" / "serialization" / "bcd_sign_nibbles.json"
    ).read_text(encoding="utf-8")
)
NIBBLE_FIELD = FieldDesc(
    name="EV_VAL",
    rfctype=RFCTYPE_BCD,
    nuc_length=NIBBLES["bytes"],
    nuc_offset=0,
    uc_length=NIBBLES["bytes"],
    uc_offset=0,
    decimals=NIBBLES["decimals"],
)


@pytest.mark.parametrize("case", NIBBLES["values"], ids=lambda c: c["case"])
def test_every_sign_nibble_decodes_as_the_reference_client_reads_it(case: dict) -> None:
    """0xB is negative (it was read as positive), 0xA/0xE decode, all-zero is zero."""
    value = decode(RFCTYPE_BCD, bytes.fromhex(case["hex"]), NIBBLE_FIELD)
    assert value == Decimal(case["value"])
    assert value.is_signed() == case["value"].startswith("-")


def test_an_all_zero_field_keeps_its_scale() -> None:
    value = decode(RFCTYPE_BCD, bytes(12), NIBBLE_FIELD)
    assert str(value) == "0.00"


def test_encode_still_emits_only_c_and_d() -> None:
    """The alternative nibbles are accepted on the way in, never produced."""
    assert encode(RFCTYPE_BCD, Decimal("123.45"), NIBBLE_FIELD)[-1] & 0x0F == 0x0C
    assert encode(RFCTYPE_BCD, Decimal("-123.45"), NIBBLE_FIELD)[-1] & 0x0F == 0x0D
