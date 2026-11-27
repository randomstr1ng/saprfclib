# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""DDIC types D16S, D34S, GGM1 and PREC in structure layouts.

Replays tests/golden/serialization/ddic_types.json: a module echoing VERI_TYPES_CV and
SADL_V_GEOM_EWKB, called live by the reference client and by saprfclib. Before, D16S,
D34S and GGM1 were unknown and dropped from the layout (ABAP refused the call), and PREC
was sent as RAW (ABAP refused its base64).
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from saprfclib.codec import (
    RFCTYPE_DECF16,
    RFCTYPE_DECF34,
    RFCTYPE_INT2,
    RFCTYPE_STRUCTURE,
    RFCTYPE_XSTRING,
)
from saprfclib.connection import (
    _build_type_desc_from_ddif,
    _join_response_frames,
    _parse_ddif_dfies_rows,
)
from saprfclib.invoke import _iter_tlv_records, xml_parameter_records
from saprfclib.types import RFC_IMPORT, FieldDesc, TypeDesc
from saprfclib.xmlparam import decode_xml_parameter, travels_as_xml

FX = json.loads(
    (Path(__file__).parent / "golden" / "serialization" / "ddic_types.json").read_text()
)


def _layout(name: str) -> TypeDesc:
    frames = iter(bytes.fromhex(h) for h in FX["ddif_reply"][name])
    reply = _join_response_frames(lambda: next(frames), "DDIF_FIELDINFO_GET")
    return _build_type_desc_from_ddif(name, _parse_ddif_dfies_rows(reply))


def _param(name: str, table: str) -> FieldDesc:
    layout = _layout(table)
    return FieldDesc(
        name, RFCTYPE_STRUCTURE, layout.nuc_size, 0, layout.uc_size, 0, 0,
        type_desc=layout, direction=RFC_IMPORT,
    )  # fmt: skip


def _piece(xml: str, name: str) -> str:
    match = re.search(rf"<{name}>.*?</{name}>", xml, re.S)
    assert match
    return match.group(0)


def test_the_layouts_keep_every_field_with_its_type() -> None:
    v = {f.name: f for f in _layout("VERI_TYPES_CV").fields}
    assert (v["F_D16S"].rfctype, v["F_D16S"].uc_length, v["F_D16S"].uc_offset) == (
        RFCTYPE_DECF16, 8, 240,
    )  # fmt: skip
    assert (v["F_D34S"].rfctype, v["F_D34S"].uc_length, v["F_D34S"].uc_offset) == (
        RFCTYPE_DECF34, 16, 256,
    )  # fmt: skip
    assert (v["F_PREC"].rfctype, v["F_PREC"].uc_length) == (RFCTYPE_INT2, 2)
    assert list(v)[-1] == "F_INT8"  # nothing after the new types was lost either
    g = {f.name: f for f in _layout("SADL_V_GEOM_EWKB").fields}
    assert (g["A_GEOM_EWKB"].rfctype, g["A_GEOM_EWKB"].uc_length) == (RFCTYPE_XSTRING, 8)


def _sent() -> dict[str, dict[str, Any]]:
    v = dict(FX["sent"]["IS_V"])
    v["F_D16S"], v["F_D34S"] = Decimal(v["F_D16S"]), Decimal(v["F_D34S"])
    g = dict(FX["sent"]["IS_G"])
    g["A_GEOM_EWKB"] = bytes.fromhex(g["A_GEOM_EWKB"])
    return {"IS_V": {"K_CHAR": "ours", **v}, "IS_G": g}


@pytest.mark.parametrize(
    ("name", "table"), [("IS_V", "VERI_TYPES_CV"), ("IS_G", "SADL_V_GEOM_EWKB")]
)
def test_the_request_is_the_xml_sent_live(name: str, table: str) -> None:
    field = _param(name, table)
    assert travels_as_xml(field)
    records = xml_parameter_records(field, _sent()[name])
    xml = b"".join(v for t, v in _iter_tlv_records(b"".join(records)) if t == 0x3C05).decode()
    assert xml == _piece(FX["saprfclib"]["request_xml"], name)


def test_the_reference_clients_xml_differs_only_in_an_untouched_float() -> None:
    ours, ref = FX["saprfclib"]["request_xml"], FX["reference"]["request_xml"]
    ours = ours.replace("<K_CHAR>ours</K_CHAR>", "<K_CHAR>ref</K_CHAR>")
    assert ours.replace("<F_FLTP>0.0000000000000000E+00</F_FLTP>", "<F_FLTP>0</F_FLTP>") == ref


def test_the_reply_decodes_with_the_values_abap_computed() -> None:
    es_v = decode_xml_parameter(
        _param("ES_V", "VERI_TYPES_CV"), _piece(FX["reference"]["reply_xml"], "ES_V").encode()
    )
    assert (es_v["F_D16S"], es_v["F_D34S"]) == (Decimal("24.690"), Decimal("-19753.08642"))
    assert (es_v["F_SCALE_16"], es_v["F_SCALE_34"], es_v["F_PREC"], es_v["F_INT8"]) == (3, 5, 4, 7)
    es_g = decode_xml_parameter(
        _param("ES_G", "SADL_V_GEOM_EWKB"),
        _piece(FX["reference"]["reply_xml"], "ES_G").encode(),
    )
    assert es_g["A_GEOM_EWKB"] == bytes.fromhex(FX["sent"]["IS_G"]["A_GEOM_EWKB"])


@pytest.mark.parametrize(
    ("code", "rfctype", "width"),
    [("n", 33, 8), ("w", 34, 8), ("d", 35, 4), ("7", 36, 4), ("x", 37, 4), ("t", 38, 4),
     ("i", 39, 2), ("c", 40, 2)],
)  # fmt: skip
def test_the_type_codes_of_types_33_to_40_decode_as_little_endian_integers(
    code: str, rfctype: int, width: int
) -> None:
    from saprfclib.codec import decode, encode
    from saprfclib.metadata import _EXID_TO_RFCTYPE

    assert _EXID_TO_RFCTYPE[code] == rfctype
    field = FieldDesc("F", rfctype, width, 0, width, 0, 0)
    raw = encode(rfctype, 258, field)
    assert raw == (258).to_bytes(width, "little")
    assert decode(rfctype, raw, field) == 258
