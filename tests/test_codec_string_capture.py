# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""STRING, XSTRING, NUM and BYTE, replayed from tests/golden/serialization/string_xstring.json."""

from __future__ import annotations

import json
import pathlib

import pytest

from saprfclib.codec import (
    RFCTYPE_BYTE,
    RFCTYPE_NUM,
    RFCTYPE_STRING,
    RFCTYPE_XSTRING,
    decode,
    encode,
)
from saprfclib.types import FieldDesc

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "serialization" / "string_xstring.json").read_text(
        encoding="utf-8"
    )
)
TYPES = {
    "STRING": RFCTYPE_STRING,
    "XSTRING": RFCTYPE_XSTRING,
    "NUM": RFCTYPE_NUM,
    "BYTE": RFCTYPE_BYTE,
}


def _field(case: dict) -> FieldDesc:
    n = case.get("length", 0)
    uc = n * 2 if case["type"] == "NUM" else n
    return FieldDesc(
        name=case["parameter"],
        rfctype=TYPES[case["type"]],
        nuc_length=n,
        nuc_offset=0,
        uc_length=uc,
        uc_offset=0,
        decimals=0,
    )


@pytest.mark.parametrize("case", FX["values"], ids=lambda c: c["parameter"])
def test_value_matches_the_capture(case: dict) -> None:
    raw = bytes.fromhex(case["hex"])
    value = bytes.fromhex(case["value_hex"]) if "value_hex" in case else case["value"]
    rfctype = TYPES[case["type"]]
    field = _field(case)
    assert decode(rfctype, raw, field) == value
    assert encode(rfctype, value, field) == raw
