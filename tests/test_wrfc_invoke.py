# tests/test_wrfc_invoke.py
#
# Offline structural tests for the wRFC invoke builder/parser (quick 260724-q0e).
#
# No network: exercises _build_ws_invoke_message and _ws_parse_invoke_response
# directly, asserting the wRFC application framing (raw TLV, no GW header, no
# COM_HEAD) and the error-surfacing contract (server E-code → AbapSystemFailure).
# The 0x5001 per-function descriptor gap (STATE.md) means live invokes return
# E=163; these tests lock the offline structure that path relies on.

import struct

import pytest

from saprfclib.connection import (
    _COM_HEAD,
    _WS_5001_HDR_WITH_VALS,
    _build_ws_invoke_message,
    _tlv_ext,
    _ws_parse_invoke_response,
)
from saprfclib.exceptions import AbapSystemFailure
from saprfclib.types import RFC_EXPORT, RFC_IMPORT, FieldDesc, FunctionDesc

_TERMINATOR = b"\xff\xff\x00\x00"


def _bootstrap_desc(unicode_mode: bool = True) -> FunctionDesc:
    """RFC_GET_FUNCTION_INTERFACE bootstrap descriptor (FUNCNAME in, PARAMS out)."""
    return FunctionDesc(
        name="RFC_GET_FUNCTION_INTERFACE",
        parameters=[
            FieldDesc(
                name="FUNCNAME",
                rfctype=0,
                nuc_length=30,
                nuc_offset=0,
                uc_length=60,
                uc_offset=0,
                decimals=0,
                unicode_mode=unicode_mode,
                direction=RFC_IMPORT,
            ),
            FieldDesc(
                name="PARAMS",
                rfctype=5,
                nuc_length=0,
                nuc_offset=0,
                uc_length=0,
                uc_offset=0,
                decimals=0,
                unicode_mode=unicode_mode,
                direction=RFC_EXPORT,
            ),
        ],
    )


def _invoke_frame() -> bytes:
    return _build_ws_invoke_message(
        "RFC_GET_FUNCTION_INTERFACE", _bootstrap_desc(), {"FUNCNAME": "STFC_CONNECTION"}
    )


def test_build_ws_invoke_starts_with_call_marker() -> None:
    # (a) subsequent invoke starts with 0x0502 (call marker).
    # Pcap-verified (frames 229/233/237/241 in websocketrfc_sniff.pcap):
    # NO session header (0x0101/0x0103/0x0106/0x0160) in post-logon invoke frames.
    # First TLV is always 0x0502 (call marker, empty value).
    frame = _invoke_frame()
    assert frame[:2] == b"\x05\x02"


def _top_level_tlv_tags(frame: bytes) -> list[int]:
    """Extract TLV tags at the outer frame level (does not recurse into 0x5001 body)."""
    tags = []
    i = 0
    while i + 4 <= len(frame):
        tag = struct.unpack_from(">H", frame, i)[0]
        if tag == 0xFFFF:
            break
        length = struct.unpack_from(">H", frame, i + 2)[0]
        tags.append(tag)
        i += 4 + length + 2  # tag(2) + len(2) + value(length) + closing_tag(2)
    return tags


def test_build_ws_invoke_contains_5001_header() -> None:
    # (b) contains the no-LZ4 HDR (0x2040 flags; 0x6040 is server→client response only).
    # FUNCNAME is CHAR → Q-marker present → byte[2]=0x02 (_WS_5001_HDR_WITH_VALS).
    # Frames without Q-markers use byte[2]=0x03 (_WS_5001_HDR).
    assert _WS_5001_HDR_WITH_VALS in _invoke_frame()


def test_build_ws_invoke_ends_with_terminator() -> None:
    # (c) ends with the 0xFFFF 0x0000 terminator
    assert _invoke_frame().endswith(_TERMINATOR)


def test_build_ws_invoke_has_no_com_head() -> None:
    # (d) no classic-RFC COM_HEAD (EBCDIC "RFC000000000")
    assert _COM_HEAD not in _invoke_frame()


def test_build_ws_invoke_no_classic_params_in_ng_rfc_mode() -> None:
    # wRFC uses NG RFC path: 0x0201/0x0203 classic param TLVs must be absent at the
    # outer frame level. Params go inside 0x5001 (ngrfc body). Sending 0x0201/0x0203
    # as outer TLVs alongside 0x5001 causes RABAX on the server side.
    frame = _invoke_frame()
    top_tags = _top_level_tlv_tags(frame)
    assert 0x0201 not in top_tags
    assert 0x0203 not in top_tags
    # Function name present in 0x0102 and ngrfc body (T-Q0E-01: no creds)
    assert "RFC_GET_FUNCTION_INTERFACE".encode("utf-16-le") in frame


def test_ws_parse_invoke_response_raises_on_ecode() -> None:
    # (e) synthetic error TLV: 0x0420 return code = 163 → AbapSystemFailure carrying "163"
    err = _tlv_ext(0x0420, struct.pack(">I", 163)) + _TERMINATOR
    with pytest.raises(AbapSystemFailure) as excinfo:
        _ws_parse_invoke_response(err, _bootstrap_desc())
    assert "163" in str(excinfo.value)


def test_ws_parse_invoke_response_raises_on_error_text() -> None:
    # 0x0402 message text carrying the E-code is surfaced too
    msg = b"CALL_FUNCTION_RECEIVE_ERROR E=163"
    err = _tlv_ext(0x0402, msg) + _TERMINATOR
    with pytest.raises(AbapSystemFailure) as excinfo:
        _ws_parse_invoke_response(err, _bootstrap_desc())
    assert "163" in str(excinfo.value)


def test_ws_parse_invoke_response_success_returns_dict() -> None:
    # success: 0x0201 name + 0x0203 UTF-16LE value → dict keyed by param name
    body = (
        _tlv_ext(0x0201, "ECHOTEXT".encode("utf-16-le"))
        + _tlv_ext(0x0203, "hello".encode("utf-16-le"))
        + _TERMINATOR
    )
    result = _ws_parse_invoke_response(body, _bootstrap_desc())
    assert result.get("ECHOTEXT") == "hello"
