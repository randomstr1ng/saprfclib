# SPDX-License-Identifier: MPL-2.0
"""The wRFC invoke frame is a classic invoke TLV stream (#14).

There is no wRFC-specific invoke format, which is the whole finding. A reference
client's invoke over WebSocket is byte-for-byte what ``build_invoke_request``
already produced for classic RFC:

    0502            request marker
    000b  UTF-16LE  release
    0102  UTF-16LE  function name
    0512            marker
    0205  UTF-16LE  one per EXPORTING parameter
    0201  UTF-16LE  parameter name
    0203  UTF-16LE  parameter value
    ffff            terminator

What this replaced sent none of the parameters. It built a 0x5001 record holding
an "ngrfc" body with Q-markers, a 0x0136 session key the server never issued, and
0x0503 and 0x0420 -- response markers appearing in a request. The server answered
with silence, exactly as it did for the malformed LOGON.

The invoke is UTF-16LE while the LOGON is single-byte, and that asymmetry is real
rather than an inconsistency to tidy away: the LOGON is exchanged in codepage
1100, which its reply reports in 0x0016, and the session moves to 4103 once
established.
"""

from __future__ import annotations

import struct

from saprfclib.codec import RFCTYPE_CHAR
from saprfclib.connection import _build_ws_invoke_frame
from saprfclib.invoke import build_invoke_request
from saprfclib.types import RFC_EXPORT, RFC_IMPORT, FieldDesc, FunctionDesc

EXPECTED_TAGS = [0x0502, 0x000B, 0x0102, 0x0512, 0x0205, 0x0205, 0x0201, 0x0203, 0xFFFF]


def _stfc() -> FunctionDesc:
    def f(name: str, direction: int) -> FieldDesc:
        return FieldDesc(
            name=name,
            rfctype=RFCTYPE_CHAR,
            nuc_length=255,
            nuc_offset=0,
            uc_length=510,
            uc_offset=0,
            decimals=0,
            unicode_mode=True,
            direction=direction,
        )

    return FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            f("REQUTEXT", RFC_IMPORT),
            f("ECHOTEXT", RFC_EXPORT),
            f("RESPTEXT", RFC_EXPORT),
        ],
    )


def _records(b: bytes) -> list[tuple[int, bytes]]:
    out, pos, n = [], 0, len(b)
    while pos + 4 <= n:
        tag, ln = struct.unpack_from(">HH", b, pos)
        pos += 4
        if tag == 0xFFFF:
            out.append((tag, b""))
            break
        if ln == 0xFFFF:
            ln = struct.unpack_from(">I", b, pos)[0]
            pos += 4
        out.append((tag, b[pos : pos + ln]))
        pos += ln
        if pos + 2 <= n and struct.unpack_from(">H", b, pos)[0] == tag:
            pos += 2
    return out


def test_the_record_set_matches_a_reference_invoke() -> None:
    frame = _build_ws_invoke_frame("STFC_CONNECTION", _stfc(), {"REQUTEXT": "probe"})
    assert [t for t, _ in _records(frame)] == EXPECTED_TAGS


def test_it_is_the_classic_invoke_stream_unchanged() -> None:
    """Not merely similar -- identical. That is why the fix is a deletion.

    If these ever diverge, one of them has stopped matching the reference and the
    difference is not a wRFC adaptation but a bug in whichever moved.
    """
    desc, params = _stfc(), {"REQUTEXT": "probe"}
    assert _build_ws_invoke_frame("STFC_CONNECTION", desc, params) == build_invoke_request(
        "STFC_CONNECTION", desc, params
    )


def test_the_parameters_are_actually_sent() -> None:
    """The old frame sent none of them.

    They went into a 0x5001 ngrfc body the server never read, so a call could not
    have worked even if the frame had been accepted.
    """
    by_tag: dict[int, list[bytes]] = {}
    for tag, val in _records(
        _build_ws_invoke_frame("STFC_CONNECTION", _stfc(), {"REQUTEXT": "probe"})
    ):
        by_tag.setdefault(tag, []).append(val)

    assert by_tag[0x0201] == ["REQUTEXT".encode("utf-16-le")]
    assert by_tag[0x0203][0].startswith("probe".encode("utf-16-le"))
    assert sorted(by_tag[0x0205]) == sorted(
        [n.encode("utf-16-le") for n in ("ECHOTEXT", "RESPTEXT")]
    )


def test_none_of_the_discarded_records_are_sent() -> None:
    """0x5001, 0x0136, 0x0503, 0x0420 and 0x0130 all had to go.

    0x0503 and 0x0420 are response markers; sending them in a request is the same
    mistake the old LOGON made. 0x0136 was a session key the server never issued.
    """
    tags = {
        t
        for t, _ in _records(
            _build_ws_invoke_frame("RFCPING", FunctionDesc(name="RFCPING", parameters=[]), {})
        )
    }
    for unwanted in (0x5001, 0x0136, 0x0503, 0x0420, 0x0130):
        assert unwanted not in tags, f"0x{unwanted:04x} must not appear in a request"


def test_the_invoke_is_utf16_while_the_logon_is_single_byte() -> None:
    """The asymmetry is real and load-bearing.

    The LOGON is exchanged in codepage 1100 and the session moves to 4103 after
    it. Making both ends of that consistent would break one of them.
    """
    from saprfclib.connection import _build_ws_logon_message

    invoke = dict(
        _records(_build_ws_invoke_frame("RFCPING", FunctionDesc(name="RFCPING", parameters=[]), {}))
    )
    logon, _ = _build_ws_logon_message(
        func_name="RFCPING", user="U", passwd="p", client="001", lang="E"
    )
    assert invoke[0x0102] == "RFCPING".encode("utf-16-le")  # 14 bytes
    assert dict(_records(logon))[0x0102] == b"RFCPING"  # 7 bytes


# --------------------------------------------------------------------------- #
# Against a real successful call
# --------------------------------------------------------------------------- #

from pathlib import Path  # noqa: E402

GOLDEN = Path(__file__).parent / "golden" / "framing"


def test_our_invoke_is_byte_identical_to_one_that_completed_a_call() -> None:
    """The strongest form this can be checked in.

    The fixture is the frame a reference client sent for STFC_CONNECTION with
    REQUTEXT='probe', in an exchange the server answered with ECHOTEXT='probe'.
    Ours is the same 648 bytes.
    """
    ours = _build_ws_invoke_frame("STFC_CONNECTION", _stfc(), {"REQUTEXT": "probe"})
    assert ours == (GOLDEN / "wrfc_invoke_request.bin").read_bytes()


def test_the_successful_response_parses_with_the_classic_parser() -> None:
    """Neither direction needed a wRFC-specific codec.

    A wRFC response is a classic response TLV stream without the GW header, which
    is why the parse side was a deletion too.
    """
    from saprfclib.invoke import parse_invoke_response

    result = parse_invoke_response((GOLDEN / "wrfc_invoke_response.bin").read_bytes(), _stfc())
    assert result["ECHOTEXT"] == "probe"


def test_a_parameterless_function_is_not_treated_as_a_failed_fetch() -> None:
    """RFC_PING has no parameters, so its interface legitimately has no rows.

    The wRFC bootstrap raised AbapSystemFailure whenever the metadata reply
    contained no parameter rows, which made every parameterless function
    uncallable over wRFC while reporting something that had not happened:
    "RFC_GET_FUNCTION_INTERFACE returned no parameter rows, no return code and no
    message". The reply had in fact succeeded.

    Whether the fetch failed is a question the reply answers directly -- 0x0417
    marks an exception and 0x0420 carries the return code -- so those are asked
    instead of inferring from the row count.
    """
    import struct as _s

    from saprfclib.invoke import tlv_record as tr
    from saprfclib.session import Session

    # A successful reply with an empty PARAMS table: success marker, zero return
    # code, no exception marker, no rows.
    reply = (
        tr(0x0500, b"") + tr(0x0503, b"") + tr(0x0420, _s.pack(">I", 0)) + _s.pack(">HH", 0xFFFF, 0)
    )
    tags = Session._parse_tlv(reply)
    assert 0x0417 not in tags, "no exception marker"
    assert _s.unpack(">I", tags[0x0420])[0] == 0, "return code zero"
    # Those two facts are what the bootstrap now consults; a row count of zero is
    # not evidence of anything.


def test_decfloat_crosses_wrfc_through_the_classic_codec() -> None:
    """The offline half of what closed #19.

    That issue asked for DECF16/DECF34 support in the wRFC ngrfc Q-markers. Those
    Q-markers no longer exist: the wRFC invoke is a classic invoke TLV stream, so
    the same codec carries these types on both transports and there is no
    separate encoder to teach.

    Verified live by calling one function module over both transports and
    comparing all nine returned values -- identical, encode and decode. This
    asserts the part that can be checked without a system: the wRFC frame builder
    produces the same bytes as the classic one for DECFLOAT parameters, so they
    cannot drift apart unnoticed.
    """
    from decimal import Decimal

    from saprfclib.codec import RFCTYPE_DECF16, RFCTYPE_DECF34
    from saprfclib.invoke import build_invoke_request

    def d(name: str, rfctype: int, width: int) -> FieldDesc:
        return FieldDesc(
            name=name,
            rfctype=rfctype,
            nuc_length=width,
            nuc_offset=0,
            uc_length=width,
            uc_offset=0,
            decimals=0,
            unicode_mode=True,
            direction=RFC_IMPORT,
        )

    desc = FunctionDesc(
        name="Z_DECF",
        parameters=[d("IV_D16", RFCTYPE_DECF16, 8), d("IV_D34", RFCTYPE_DECF34, 16)],
    )
    params = {"IV_D16": Decimal("42.0"), "IV_D34": Decimal("-1")}

    assert _build_ws_invoke_frame("Z_DECF", desc, params) == build_invoke_request(
        "Z_DECF", desc, params
    )

    # And the value really is DPD little-endian, as settled in #13 -- 42.0 is
    # 22 34 ... 02 20 as IEEE lays it out and arrives reversed on the wire.
    values = [v for t, v in _records(_build_ws_invoke_frame("Z_DECF", desc, params)) if t == 0x0203]
    assert values[0] == bytes.fromhex("2002000000003422")
