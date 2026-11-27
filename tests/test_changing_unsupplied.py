# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""An unsupplied optional CHANGING parameter is sent as the reference client sends it.

Replays tests/golden/framing/changing_unsupplied.json: a flat one goes with its initial
value, a deep one not at all. ABAP reported both flat parameters as supplied either way.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from saprfclib.codec import RFCTYPE_CHAR, RFCTYPE_INT, RFCTYPE_STRING, RFCTYPE_STRUCTURE
from saprfclib.invoke import _iter_tlv_records, build_invoke_request, tlv_record
from saprfclib.types import (
    RFC_CHANGING,
    RFC_EXPORT,
    RFC_IMPORT,
    FieldDesc,
    FunctionDesc,
    TypeDesc,
)

FX = json.loads(
    (Path(__file__).parent / "golden" / "framing" / "changing_unsupplied.json").read_text()
)

# The interface as RFC_GET_FUNCTION_INTERFACE reported it, in its order.
CHG = FunctionDesc(
    "Z_SAPRFCLIB_CHG",
    [
        FieldDesc("CV_C", RFCTYPE_CHAR, 10, 0, 20, 0, 0, direction=RFC_CHANGING),
        FieldDesc("CV_N", RFCTYPE_INT, 4, 0, 4, 0, 0, direction=RFC_CHANGING),
        FieldDesc("EV_SUPPLIED", RFCTYPE_CHAR, 40, 0, 80, 0, 0, direction=RFC_EXPORT),
    ],
)

_DEEP_ROW = TypeDesc("ZSAPRFCLIB_DEEP", [FieldDesc("STR", RFCTYPE_STRING, 8, 0, 8, 0, 0)], 8, 8)


def _deep(name: str, direction: int) -> FieldDesc:
    return FieldDesc(
        name, RFCTYPE_STRUCTURE, 8, 0, 8, 0, 0, type_desc=_DEEP_ROW, direction=direction
    )


DEEP = FunctionDesc(
    "Z_SAPRFCLIB_DEEP",
    [
        _deep("CS_DEEP", RFC_CHANGING),
        _deep("ES_DEEP", RFC_EXPORT),
        _deep("ES_FLAT", RFC_EXPORT),
        _deep("ET_CPLX", RFC_EXPORT),
        _deep("ET_RET", RFC_EXPORT),
        FieldDesc("EV_STR", RFCTYPE_STRING, 8, 0, 8, 0, 0, direction=RFC_EXPORT),
        _deep("IS_DEEP", RFC_IMPORT),
    ],
)


def _from_function_name(request: bytes) -> bytes:
    recs = list(_iter_tlv_records(request))
    start = next(i for i, (t, _) in enumerate(recs) if t == 0x0102)
    return b"".join(tlv_record(t, v) for t, v in recs[start:])


@pytest.mark.parametrize(
    ("case", "desc", "params"),
    [
        ("chg_none", CHG, {}),
        ("chg_both", CHG, {"CV_N": 41, "CV_C": "given"}),
        ("deep_none", DEEP, {}),
    ],
)
def test_the_request_is_the_reference_clients(
    case: str, desc: FunctionDesc, params: dict[str, object]
) -> None:
    built = _from_function_name(build_invoke_request(desc.name, desc, params))
    live = _from_function_name(bytes.fromhex(FX["reference"][case]))
    assert built == live


def test_an_unsupplied_flat_changing_value_is_its_initial_value() -> None:
    recs = list(_iter_tlv_records(build_invoke_request(CHG.name, CHG, {})))
    values = {
        recs[i][1].decode("utf-16-le"): recs[i + 1][1]
        for i in range(len(recs) - 1)
        if recs[i][0] == 0x0201 and recs[i + 1][0] == 0x0203
    }
    assert values == {"CV_C": " ".encode("utf-16-le") * 10, "CV_N": bytes(4)}


def test_a_tRFC_call_still_leaves_it_out() -> None:
    recs = list(_iter_tlv_records(build_invoke_request(CHG.name, CHG, {}, transactional=True)))
    assert not any(t == 0x0201 for t, _ in recs)
