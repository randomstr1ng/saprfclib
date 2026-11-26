# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Deep structures and table-typed parameters travel as XML (#85).

A structure with a STRING, XSTRING or table component used to be laid into a fixed
buffer, with the variable-length value writing over the components after it, and its
metadata code ('v') was read as DECFLOAT16. A table-typed IMPORTING parameter was
sent as a binary table, which the server refuses. Everything here replays live
captures of the reference client and of saprfclib against ABAP Platform 2025
(tests/golden/serialization/deep/deep.json).
"""

from __future__ import annotations

import asyncio
import struct
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from saprfclib.codec import RFCTYPE_CHAR, RFCTYPE_STRUCTURE, RFCTYPE_TABLE, encode
from saprfclib.connection import (
    AsyncConnection,
    Connection,
    _build_type_desc_from_ddif,
    _parse_ddif_dfies_rows,
    _parse_gfi_params_rows,
    _strip_gw_header,
)
from saprfclib.exceptions import IncompleteDescriptorError
from saprfclib.invoke import (
    _iter_tlv_records,
    build_invoke_request,
    dm_table_ids,
    parse_invoke_response,
)
from saprfclib.metadata import _parse_params_row
from saprfclib.types import RFC_IMPORT, RFC_TABLES, FieldDesc, FunctionDesc, TypeDesc
from saprfclib.xmlparam import (
    XML_CHUNK_BYTES,
    decode_xml_parameter,
    encode_xml_parameter,
    is_deep,
    travels_as_xml,
)

from ._mocks import AsyncMockTransport, MockTransport
from .test_connection import _handshake_responses

DEEP = Path(__file__).parent / "golden" / "serialization" / "deep"

_MARK, _DATA = 0x3C02, 0x3C05


def _frame(name: str) -> bytes:
    """A captured NI frame without its 4-byte length prefix."""
    raw = (DEEP / name).read_bytes()
    (length,) = struct.unpack(">I", raw[:4])
    assert length == len(raw) - 4
    return raw[4:]


def _records(frame: bytes) -> list[tuple[int, bytes]]:
    """TLV records of a captured frame (GW header first) or of a built request."""
    return list(_iter_tlv_records(_strip_gw_header(frame) if frame[:1] == b"\x06" else frame))


def _xml_params(frame: bytes) -> list[bytes]:
    """The XML document of every 0x3c02 bracket in a frame, in order."""
    out: list[bytes] = []
    current: list[bytes] | None = None
    for tag, value in _records(frame):
        if tag == _MARK:
            if current is None:
                current = []
            else:
                out.append(b"".join(current))
                current = None
        elif tag == _DATA and current is not None:
            current.append(value)
    return out


def _binary_values(frame: bytes) -> dict[str, bytes]:
    recs = _records(frame)
    return {
        recs[i][1].decode("utf-16-le"): recs[i + 1][1]
        for i in range(len(recs) - 1)
        if recs[i][0] == 0x0201 and recs[i + 1][0] == 0x0203
    }


METADATA_SEQUENCE = [
    "gfi_response.bin",
    "ddif_deep_response.bin",
    "ddif_ttyp_response.bin",
    "rgsd_bapiret2_t_response.bin",
    "ddif_ttyp_stfccplxt_t_response.bin",
    "rgsd_stfccplxt_t_response.bin",
    "ddif_flat_response.bin",
]


def _connection(*after: bytes) -> tuple[Connection, MockTransport]:
    responses = _handshake_responses() + [_frame(n) for n in METADATA_SEQUENCE] + list(after)
    transport = MockTransport(responses)
    conn = Connection(transport)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    return conn, transport


_DESC: FunctionDesc | None = None


def _desc() -> FunctionDesc:
    """Z_SAPRFCLIB_DEEP's interface, resolved from the captured metadata replies."""
    global _DESC
    if _DESC is None:
        conn, _ = _connection()
        _DESC = conn._call_bootstrap("Z_SAPRFCLIB_DEEP")
    return _DESC


def _param(name: str) -> FieldDesc:
    return next(p for p in _desc().parameters if p.name == name)


FLAT = {
    "C": "Ab <&>",
    "N": "42",
    "D": "20261126",
    "T": "235959",
    "P": Decimal("-1234.56"),
    "F": 1.5,
    "I1": 255,
    "I2": -32768,
    "I4": -7,
    "I8": 9007199254740993,
    "X": b"\x00\xff\x10\x20",
    "DF16": Decimal("12.5"),
    "DF34": Decimal("-0.001"),
    "TS": "2026-11-26T12:34:56.1234567",
}
DEEP_VALUE = {
    "ID": 1,
    "STR": "Grüße\n\t \"q\" 'a' ]]> é\U0001d11e",
    "XSTR": b"\x00\x01\x02",
    "FLAT": FLAT,
    "CPLX": {"I": 2, "C": "cx", "STR": "s", "XSTR": b"\xff"},
    "RETS": [
        {"TYPE": "E", "ID": "00", "NUMBER": "001", "MESSAGE": "m1 <x>"},
        {"TYPE": "W", "MESSAGE": ""},
    ],
    "CPLXT": [
        {"I": 3, "C": "t1", "STR": "a", "XSTR": b"\x01"},
        {"I": 4, "C": "", "STR": "", "XSTR": b""},
    ],
}
# What the reference client decoded the echo back to (deep.json).
FLAT_BACK = {**FLAT, "N": "000042"}
_RET_BLANK = {
    "LOG_NO": "",
    "LOG_MSG_NO": "000000",
    "MESSAGE_V1": "",
    "MESSAGE_V2": "",
    "MESSAGE_V3": "",
    "MESSAGE_V4": "",
    "PARAMETER": "",
    "ROW": 0,
    "FIELD": "",
    "SYSTEM": "",
}
DEEP_BACK = {
    **DEEP_VALUE,
    "FLAT": FLAT_BACK,
    "RETS": [
        {"TYPE": "E", "ID": "00", "NUMBER": "001", "MESSAGE": "m1 <x>", **_RET_BLANK},
        {"TYPE": "W", "ID": "", "NUMBER": "000", "MESSAGE": "", **_RET_BLANK},
    ],
}


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #


def test_exid_v_is_a_deep_structure_not_a_decfloat() -> None:
    rows = _parse_gfi_params_rows(_frame("gfi_response.bin"), unicode_mode=True)
    types = {r["PARAMETER"]: (r["EXID"], _parse_params_row(r).rfctype) for r in rows}
    assert types["IS_DEEP"] == ("v", RFCTYPE_STRUCTURE)
    assert types["CS_DEEP"] == ("v", RFCTYPE_STRUCTURE)
    assert types["IS_FLAT"] == ("u", RFCTYPE_STRUCTURE)
    assert types["IT_RET"] == ("h", RFCTYPE_TABLE)


def test_named_components_are_rebuilt_as_nested_structures() -> None:
    rows = _parse_ddif_dfies_rows(_frame("ddif_deep_response.bin"))
    seen: list[str] = []

    def resolve(name: str) -> TypeDesc:
        seen.append(name)
        return TypeDesc(name, [], 0, 0)

    td = _build_type_desc_from_ddif("ZSAPRFCLIB_DEEP", rows, resolve)
    assert [f.name for f in td.fields] == ["ID", "STR", "XSTR", "FLAT", "CPLX", "RETS", "CPLXT"]
    flat = td.fields[3]
    assert flat.rfctype == RFCTYPE_STRUCTURE and flat.type_desc is not None
    assert flat.type_desc.name == "ZSAPRFCLIB_FLAT"
    assert [f.name for f in flat.type_desc.fields][:3] == ["C", "N", "D"]
    # Offsets inside a component are relative to it.
    assert flat.type_desc.fields[0].uc_offset == 0
    assert td.fields[5].rfctype == RFCTYPE_TABLE
    assert seen == ["BAPIRET2_T", "STFCCPLXT_T"]


def test_a_connection_resolves_every_level_of_a_deep_interface() -> None:
    desc = _desc()
    deep = _param("IS_DEEP")
    assert deep.type_desc is not None and is_deep(deep.type_desc)
    comps = {f.name: f for f in deep.type_desc.fields}
    rets, cplxt = comps["RETS"].type_desc, comps["CPLXT"].type_desc
    assert rets is not None and len(rets.fields) == 14
    assert cplxt is not None and [f.name for f in cplxt.fields] == ["I", "C", "STR", "XSTR"]
    assert not is_deep(_param("IS_FLAT").type_desc)  # type: ignore[arg-type]
    assert len(desc.parameters) == 11


# --------------------------------------------------------------------------- #
# Which parameters go as XML
# --------------------------------------------------------------------------- #


def test_routing_matches_the_reference_client() -> None:
    # echo_reference_request: IS_DEEP as XML, IS_FLAT and IV_STR binary.
    assert travels_as_xml(_param("IS_DEEP"))
    assert not travels_as_xml(_param("IS_FLAT"))
    assert not travels_as_xml(_param("IV_STR"))
    # multi_reference_request: a table-typed IMPORTING parameter is XML even with
    # flat rows; sent binary, the server refused it (CALL_FUNCTION_ILLEGAL_P_TYPE).
    assert travels_as_xml(_param("IT_RET"))
    tables = FieldDesc("T", RFCTYPE_TABLE, 0, 0, 0, 0, 0, direction=RFC_TABLES)
    tables.type_desc = _param("IT_RET").type_desc
    assert not travels_as_xml(tables)


def test_the_request_carries_xml_and_binary_parameters_as_the_reference_does() -> None:
    request = build_invoke_request(
        "Z_SAPRFCLIB_DEEP", _desc(), {"IS_DEEP": DEEP_VALUE, "IS_FLAT": FLAT, "IV_STR": "top"}
    )
    reference = _frame("echo_reference_request.bin")
    ours_xml = _xml_params(request)
    ref_xml = _xml_params(reference)
    # The one difference: the client wrote the float as 1.5, saprfclib writes the
    # form the server itself writes (and reads back exactly).
    assert ours_xml == [ref_xml[0].replace(b"<F>1.5</F>", b"<F>1.5000000000000000E+00</F>")]
    # The flat structure and the top-level STRING are byte-identical binary values.
    ours_bin = _binary_values(request)
    ref_bin = _binary_values(reference)
    assert ours_bin == ref_bin


def test_each_deep_parameter_gets_its_own_bracket() -> None:
    values = {
        "CS_DEEP": {"ID": 41, "STR": "chg"},
        "IS_DEEP": {"ID": 1, "STR": "d1"},
        "IT_CPLX": [{"I": 9, "C": "c", "STR": "z", "XSTR": b"\x07"}],
        "IT_RET": [{"TYPE": "S", "MESSAGE": "flat row"}],
    }
    ours = _xml_params(build_invoke_request("Z_SAPRFCLIB_DEEP", _desc(), values))
    ref = _xml_params(_frame("multi_reference_request.bin"))
    assert len(ours) == len(ref) == 4
    # The reference client sends an untouched component as an empty element, and
    # saprfclib writes its initial value; the server reads both as the same thing.
    for name, a, b in zip(values, ours, ref, strict=True):
        assert decode_xml_parameter(_param(name), a) == decode_xml_parameter(_param(name), b)


def test_an_empty_table_is_sent_as_an_empty_element() -> None:
    # The reference client sends <IMPORT_TAB></IMPORT_TAB> for an empty
    # STFC_DEEP_TABLE table (live capture, 2026-11-26).
    assert encode_xml_parameter(_param("IT_CPLX"), []) == b"<IT_CPLX></IT_CPLX>"
    request = build_invoke_request("Z_SAPRFCLIB_DEEP", _desc(), {"IT_CPLX": []})
    assert _xml_params(request) == [b"<IT_CPLX></IT_CPLX>"]


def test_xml_tables_take_no_dm_table_id() -> None:
    assert dm_table_ids(_desc(), {"IT_RET": [{"TYPE": "S"}]}) == {}


def test_a_long_value_is_cut_into_16384_byte_records() -> None:
    rows = [{"I": i, "STR": "y" * 100, "XSTR": bytes(20)} for i in range(400)]
    request = build_invoke_request("Z_SAPRFCLIB_DEEP", _desc(), {"IT_CPLX": rows})
    sizes = [len(v) for t, v in _iter_tlv_records(request) if t == _DATA]
    document = encode_xml_parameter(_param("IT_CPLX"), rows)
    assert sum(sizes) == len(document) > 2 * XML_CHUNK_BYTES
    assert all(s == XML_CHUNK_BYTES for s in sizes[:-1]) and 0 < sizes[-1] <= XML_CHUNK_BYTES


def test_escaping_matches_the_reference_client() -> None:
    # stfc_deep_structure_request: & < > as character references, the rest as is.
    xml = _xml_params(_frame("stfc_deep_structure_request.bin"))[0]
    assert b"<STR>H\xc3\xa4llo &#60;&#38;&#62; 'x\"</STR>" in xml


def test_a_deep_parameter_in_a_trfc_unit_is_refused() -> None:
    with pytest.raises(NotImplementedError, match="tRFC"):
        build_invoke_request(
            "Z_SAPRFCLIB_DEEP", _desc(), {"IS_DEEP": {"ID": 1}}, transactional=True
        )


# --------------------------------------------------------------------------- #
# Replies
# --------------------------------------------------------------------------- #


def test_the_reference_reply_decodes_to_what_the_reference_client_read() -> None:
    result = parse_invoke_response(_strip_gw_header(_frame("echo_reference_response.bin")), _desc())
    assert result["ES_DEEP"] == DEEP_BACK
    assert result["ES_FLAT"] == FLAT_BACK
    assert result["EV_STR"] == "top"


def test_xml_and_binary_parameters_interleaved_in_a_reply() -> None:
    result = parse_invoke_response(
        _strip_gw_header(_frame("multi_reference_response.bin")), _desc()
    )
    assert result["CS_DEEP"]["ID"] == 42 and result["CS_DEEP"]["STR"] == "chg"
    assert result["ES_DEEP"]["STR"] == "d1"
    assert result["ES_DEEP"]["FLAT"]["D"] == ""  # 0000-00-00 is the initial date
    assert result["ES_DEEP"]["FLAT"]["TS"] is None  # 0 is the initial UTCLONG
    assert result["ES_DEEP"]["FLAT"]["X"] == bytes(4)
    assert result["ET_CPLX"] == [{"I": 9, "C": "c", "STR": "z", "XSTR": b"\x07"}]
    assert result["ET_RET"][0]["MESSAGE"] == "flat row"
    assert result["EV_STR"] == ""


def test_the_server_escapes_quotes_too() -> None:
    desc = FunctionDesc("STFC_DEEP_STRUCTURE", [_echostruct()])
    result = parse_invoke_response(
        _strip_gw_header(_frame("stfc_deep_structure_response.bin")), desc
    )
    assert result["ECHOSTRUCT"] == {
        "I": 7,
        "C": "AbC",
        "STR": "Hällo <&> 'x\"",
        "XSTR": b"\x00\x01\xff\xde\xad",
    }


def _echostruct() -> FieldDesc:
    cplx = _param("IS_DEEP").type_desc.fields[4]  # type: ignore[union-attr]
    return FieldDesc(
        "ECHOSTRUCT", RFCTYPE_STRUCTURE, 0, 0, 0, 0, 0, type_desc=cplx.type_desc, direction=2
    )


def test_a_saprfclib_call_end_to_end() -> None:
    conn, transport = _connection(_frame("echo_saprfclib_response.bin"))
    result = conn.call("Z_SAPRFCLIB_DEEP", IS_DEEP={"ID": 1, "STR": "d1", "RETS": [{"TYPE": "S"}]})
    assert result["ES_DEEP"]["ID"] == 1 and result["ES_DEEP"]["RETS"][0]["TYPE"] == "S"
    live = _frame("echo_saprfclib_request.bin")
    assert _xml_params(transport.sent[-1]) == _xml_params(live)


def test_an_async_connection_resolves_and_calls_the_same_way() -> None:
    async def main() -> dict[str, Any]:
        responses = [_frame(n) for n in METADATA_SEQUENCE] + [_frame("echo_saprfclib_response.bin")]
        sync_conn, _ = _connection()
        transport = AsyncMockTransport(responses)
        conn = AsyncConnection(transport)
        conn._session = sync_conn._session  # READY, with the logon's attributes
        return await conn.call("Z_SAPRFCLIB_DEEP", IS_DEEP={"ID": 1, "STR": "d1"})

    result = asyncio.run(main())
    assert result["ES_DEEP"]["ID"] == 1


# --------------------------------------------------------------------------- #
# What is refused
# --------------------------------------------------------------------------- #


def _cplx_param() -> FieldDesc:
    return _param("IT_CPLX")


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (
            b"<IT_CPLX><item><I>1</I><C></C><STR></STR><XSTR></XSTR><NEW>x</NEW></item></IT_CPLX>",
            "invalidate_metadata",
        ),
        (b"<IT_CPLX><item><I>1</I><C></C></item></IT_CPLX>", "sent no STR, XSTR"),
        (b"<IT_CPLX><row></row></IT_CPLX>", "unexpected <row>"),
        (
            b"<IT_CPLX><item><I>x</I><C></C><STR></STR><XSTR></XSTR></item></IT_CPLX>",
            "not an integer",
        ),
        (
            b"<IT_CPLX><item><I>1</I><C></C><STR></STR><XSTR>!!</XSTR></item></IT_CPLX>",
            "IT_CPLX\\[0\\]-XSTR",
        ),
        (b"<IT_CPLX><item>", "never closed"),
        (b"<IT_CPLX></ET_CPLX>", "does not match"),
        (b'<IT_CPLX a="1"></IT_CPLX>', "unsupported markup"),
        (b"<!DOCTYPE x><IT_CPLX></IT_CPLX>", "unsupported markup"),
        (b"<ET_CPLX></ET_CPLX>", "is for <ET_CPLX>"),
        (b"\xff", "not UTF-8"),
    ],
)
def test_malformed_xml_is_refused_with_its_place(payload: bytes, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        decode_xml_parameter(_cplx_param(), payload)


def test_a_namespaced_component_name_is_refused_not_guessed() -> None:
    row = TypeDesc("ZROW", [FieldDesc("/ABC/F", RFCTYPE_CHAR, 2, 0, 4, 0, 0)], 2, 4)
    field = FieldDesc("IT", RFCTYPE_TABLE, 0, 0, 0, 0, 0, type_desc=row, direction=RFC_IMPORT)
    with pytest.raises(NotImplementedError, match="namespaced"):
        encode_xml_parameter(field, [{"/ABC/F": "x"}])


def test_an_unresolved_table_type_is_refused() -> None:
    field = FieldDesc("IT", RFCTYPE_TABLE, 0, 0, 0, 0, 0, direction=RFC_IMPORT)
    with pytest.raises(IncompleteDescriptorError):
        encode_xml_parameter(field, [{"A": 1}])


def test_raw_longer_than_its_field_is_refused() -> None:
    with pytest.raises(ValueError, match="RAW\\(4\\)"):
        encode_xml_parameter(_param("IS_DEEP"), {"FLAT": {"X": b"12345"}})


def test_a_decfloat_left_out_of_a_flat_structure_is_initial() -> None:
    # Before #85 the default was "", which the decimal encoder could not parse.
    flat = _param("IS_FLAT")
    encode(RFCTYPE_STRUCTURE, {"C": "x"}, flat)


# --------------------------------------------------------------------------- #
# Properties
# --------------------------------------------------------------------------- #

_text = st.text(st.characters(exclude_categories=("Cs",), exclude_characters="\x00"), max_size=12)
_cplx_rows = st.lists(
    st.fixed_dictionaries(
        {
            "I": st.integers(-(2**31), 2**31 - 1),
            "C": st.text(st.characters(codec="ascii", exclude_characters="\x00"), max_size=10).map(
                str.rstrip
            ),
            "STR": _text,
            "XSTR": st.binary(max_size=16),
        }
    ),
    max_size=4,
)


@settings(max_examples=60, deadline=None)
@given(rows=_cplx_rows, nested=st.lists(_cplx_rows, max_size=3))
def test_what_is_encoded_decodes_to_the_same_value(rows: list[Any], nested: list[Any]) -> None:
    deep = {"ID": 5, "STR": "s", "CPLXT": rows, "CPLX": rows[0] if rows else {}}
    back = decode_xml_parameter(_param("IS_DEEP"), encode_xml_parameter(_param("IS_DEEP"), deep))
    assert back["CPLXT"] == rows
    assert decode_xml_parameter(_cplx_param(), encode_xml_parameter(_cplx_param(), rows)) == rows


@settings(max_examples=300, deadline=None)
@given(data=st.data())
def test_a_mutated_reply_raises_only_typed_errors(data: st.DataObject) -> None:
    payload = bytearray(b"".join(_xml_params(_frame("echo_reference_response.bin"))))
    for _ in range(data.draw(st.integers(1, 4))):
        at = data.draw(st.integers(0, len(payload) - 1))
        payload[at] = data.draw(st.integers(0, 255))
    try:
        decode_xml_parameter(_param("ES_DEEP"), bytes(payload))
    except (ValueError, NotImplementedError):
        pass


# --------------------------------------------------------------------------- #
# The RFC server side
# --------------------------------------------------------------------------- #
# ABAP calling STFC_DEEP_TABLE / STFC_DEEP_STRUCTURE through a registered
# destination, answered once by the reference SDK's server and once by
# saprfclib's (deep.json, "server_side").


def _resptext() -> FieldDesc:
    return FieldDesc("RESPTEXT", RFCTYPE_CHAR, 255, 0, 510, 0, 0, direction=2)


def _server_descs() -> dict[str, FunctionDesc]:
    row = _param("IT_CPLX").type_desc

    def tab(name: str, direction: int) -> FieldDesc:
        return FieldDesc(name, RFCTYPE_TABLE, 0, 0, 40, 0, 0, type_desc=row, direction=direction)

    def struct_(name: str, direction: int) -> FieldDesc:
        return FieldDesc(
            name, RFCTYPE_STRUCTURE, 0, 0, 40, 0, 0, type_desc=row, direction=direction
        )

    return {
        "STFC_DEEP_TABLE": FunctionDesc(
            "STFC_DEEP_TABLE", [tab("EXPORT_TAB", 2), _resptext(), tab("IMPORT_TAB", 1)]
        ),
        "STFC_DEEP_STRUCTURE": FunctionDesc(
            "STFC_DEEP_STRUCTURE",
            [struct_("ECHOSTRUCT", 2), _resptext(), struct_("IMPORTSTRUCT", 1)],
        ),
    }


def _echo_server() -> tuple[Any, list[dict[str, Any]]]:
    from saprfclib.server import RfcServer

    server = RfcServer({"program_id": "ZTEST", "gwhost": "gw.example", "gwserv": "sapgw00"})
    seen: list[dict[str, Any]] = []
    descs = _server_descs()

    @server.function("STFC_DEEP_TABLE", descs["STFC_DEEP_TABLE"])
    def _table(req: dict[str, Any]) -> dict[str, Any]:
        seen.append(req)
        return {"EXPORT_TAB": req["IMPORT_TAB"], "RESPTEXT": "x"}

    @server.function("STFC_DEEP_STRUCTURE", descs["STFC_DEEP_STRUCTURE"])
    def _struct(req: dict[str, Any]) -> dict[str, Any]:
        seen.append(req)
        return {"ECHOSTRUCT": req["IMPORTSTRUCT"], "RESPTEXT": "x"}

    return server, seen


@pytest.mark.parametrize(
    ("request_frame", "reference_reply", "expected"),
    [
        (
            "server_deep_table_request.bin",
            "server_deep_table_reference_reply.bin",
            {
                "IMPORT_TAB": [
                    {"I": 3, "C": "deep", "STR": "string value <&>", "XSTR": b"\x01\x02\xff"},
                    {"I": 4, "C": "deep", "STR": "string value <&>", "XSTR": b"\x01\x02\xff"},
                ]
            },
        ),
        (
            "server_deep_structure_request.bin",
            "server_deep_structure_reference_reply.bin",
            {"IMPORTSTRUCT": {"I": 5, "C": "ds", "STR": "deep struct", "XSTR": b"\xca\xfe"}},
        ),
    ],
)
def test_the_rfc_server_reads_and_answers_deep_parameters_as_the_reference_server(
    request_frame: str, reference_reply: str, expected: dict[str, Any]
) -> None:
    server, seen = _echo_server()
    reply = server.dispatch_inbound(_frame(request_frame))
    assert seen == [expected]
    # The XML saprfclib answers with is the reference server's, byte for byte.
    assert _xml_params(reply) == _xml_params(_frame(reference_reply))


def test_the_live_saprfclib_server_replies_are_what_the_code_writes() -> None:
    server, _ = _echo_server()
    for request, live in (
        ("server_deep_table_request.bin", "server_deep_table_saprfclib_reply.bin"),
        ("server_deep_structure_request.bin", "server_deep_structure_saprfclib_reply.bin"),
    ):
        assert _xml_params(server.dispatch_inbound(_frame(request))) == _xml_params(_frame(live))
