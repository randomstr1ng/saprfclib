# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""INT8 and UTCLONG on the wire, replayed from tests/golden/serialization/int8_utclong.json.

The fixture holds what the reference client sent and received for a purpose-built
function module with INT8, UTCLONG, DATN and TIMN parameters.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib.codec import (
    RFCTYPE_DATE,
    RFCTYPE_INT8,
    RFCTYPE_TIME,
    RFCTYPE_UTCLONG,
    decode,
    encode,
)
from saprfclib.metadata import _DATATYPE_TO_RFCTYPE, _EXID_TO_RFCTYPE
from saprfclib.types import FieldDesc

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "serialization" / "int8_utclong.json").read_text(
        encoding="utf-8"
    )
)


def _field(rfctype: int, uc: int) -> FieldDesc:
    return FieldDesc(
        name="X",
        rfctype=rfctype,
        nuc_length=uc,
        nuc_offset=0,
        uc_length=uc,
        uc_offset=0,
        decimals=0,
    )


INT8 = _field(RFCTYPE_INT8, 8)
UTCL = _field(RFCTYPE_UTCLONG, 8)


@pytest.mark.parametrize("case", FX["int8"], ids=lambda c: c["parameter"])
def test_int8_matches_the_capture(case: dict) -> None:
    raw = bytes.fromhex(case["hex"])
    assert decode(RFCTYPE_INT8, raw, INT8) == case["value"]
    assert encode(RFCTYPE_INT8, case["value"], INT8) == raw


@pytest.mark.parametrize("case", FX["utclong"], ids=lambda c: str(c["value"]))
def test_utclong_matches_the_capture(case: dict) -> None:
    raw = bytes.fromhex(case["hex"])
    assert decode(RFCTYPE_UTCLONG, raw, UTCL) == case["value"]
    assert encode(RFCTYPE_UTCLONG, case["value"], UTCL) == raw


def test_utclong_accepts_what_the_reference_client_accepts() -> None:
    ref = encode(RFCTYPE_UTCLONG, "2026-11-12T10:21:26.1234567", UTCL)
    assert encode(RFCTYPE_UTCLONG, "2026-11-12T10:21:26.1234567Z", UTCL) == ref
    aware = dt.datetime(2026, 11, 12, 11, 21, 26, 123456, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    assert decode(RFCTYPE_UTCLONG, encode(RFCTYPE_UTCLONG, aware, UTCL), UTCL) == (
        "2026-11-12T10:21:26.1234560"
    )
    assert encode(RFCTYPE_UTCLONG, None, UTCL) == bytes(8)


@pytest.mark.parametrize(
    "bad",
    [
        "1582-10-10T00:00:00.0000000",  # refused by the reference client: calendar gap
        "2026-11-12 10:21:26",  # refused by the reference client: format
        "1900-02-29T00:00:00",  # no such Gregorian day
        "2026-13-01T00:00:00",
    ],
)
def test_utclong_refuses_what_does_not_exist(bad: str) -> None:
    with pytest.raises(ValueError):
        encode(RFCTYPE_UTCLONG, bad, UTCL)


@given(st.integers(min_value=1, max_value=3155380704000000000))
def test_utclong_decode_encode_roundtrip(raw: int) -> None:
    b = raw.to_bytes(8, "little", signed=True)
    text = decode(RFCTYPE_UTCLONG, b, UTCL)
    assert encode(RFCTYPE_UTCLONG, text, UTCL) == b


@given(st.integers(min_value=-(2**63), max_value=2**63 - 1))
def test_int8_roundtrip(v: int) -> None:
    assert decode(RFCTYPE_INT8, encode(RFCTYPE_INT8, v, INT8), INT8) == v


def test_metadata_knows_the_observed_type_codes() -> None:
    assert _EXID_TO_RFCTYPE["8"] == RFCTYPE_INT8
    assert _EXID_TO_RFCTYPE["p"] == RFCTYPE_UTCLONG
    assert _DATATYPE_TO_RFCTYPE["DATN"] == RFCTYPE_DATE
    assert _DATATYPE_TO_RFCTYPE["TIMN"] == RFCTYPE_TIME


def test_datn_timn_travel_as_date_and_time() -> None:
    d = FX["datn_timn"]
    assert decode(RFCTYPE_DATE, bytes.fromhex(d["IV_DATN"]), _field(RFCTYPE_DATE, 16)) == "20261112"
    assert decode(RFCTYPE_TIME, bytes.fromhex(d["IV_TIMN"]), _field(RFCTYPE_TIME, 12)) == "102126"
