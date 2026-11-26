# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""RfcServer receives bgRFC units as ABAP sends them (#119).

Replays tests/golden/trfc/bgrfc_inbound.json: ABAP sending units through a registered
destination, first to the reference SDK's server, then to saprfclib's, with what ABAP
did with each answer.
"""

from __future__ import annotations

import struct
from typing import Any

import pytest

from saprfclib.invoke import (
    _iter_tlv_records,
    bgrfc_unit_type_from_kind,
    build_bgrfc_sdata,
    parse_bgrfc_sdata,
)
from saprfclib.server import RfcServer
from saprfclib.stores import InMemoryUnitStore, UnitState

from ._bgrfc_fixture import descriptors
from ._bgrfc_inbound import live, live_calls, ship_frame, unit_frame

UID = "BC2411CF03C01FE1BABBEDD62BE8E069"


def _server() -> tuple[RfcServer, list[str], list[tuple[str, str, str]]]:
    server = RfcServer({"program_id": "ZTEST", "gwhost": "gw.example", "gwserv": "sapgw00"})
    ran: list[str] = []
    events: list[tuple[str, str, str]] = []

    @server.function("STFC_CONNECTION", descriptors()["STFC_CONNECTION"])
    def _stfc(request: dict[str, Any]) -> dict[str, Any]:
        ran.append(request["REQUTEXT"])
        return {}

    def note(name: str) -> Any:
        return lambda uid, ut: events.append((name, uid, ut))

    server.install_unit_handlers(
        commit=note("commit"), rollback=note("rollback"), confirm=note("confirm")
    )
    return server, ran, events


def _values(frame: bytes) -> list[tuple[str, bytes]]:
    recs = list(_iter_tlv_records(frame))
    return [
        (recs[i][1].decode("utf-16-le"), recs[i + 1][1])
        for i in range(len(recs) - 1)
        if recs[i][0] == 0x0201 and recs[i + 1][0] == 0x0203
    ]


# --------------------------------------------------------------------------- #
# What ABAP sends
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("key", "calls", "unit_type", "queue"),
    [
        ("t_ship", ["STFC_CONNECTION"], "T", ""),
        ("d_ship", ["Z_SAPRFCLIB_DEEP2", "STFC_CONNECTION"], "T", ""),
        ("q_ship", ["STFC_CONNECTION"], "Q", "ZSAPRFCLIB_OQ"),
    ],
)
def test_abap_sends_the_unit_in_the_clients_layout(
    key: str, calls: list[str], unit_type: str, queue: str
) -> None:
    sstate = dict(_values(live("reference", key)))["SSTATE"]
    (kind,) = struct.unpack_from("<i", sstate, 16)
    assert bgrfc_unit_type_from_kind(kind) == unit_type
    assert sstate[84:164].decode("utf-16-le").rstrip() == queue
    found = live_calls("reference", key)
    assert [name for name, _ in found] == calls
    # Written again by the client's builder, the calls read back unchanged.
    assert parse_bgrfc_sdata(build_bgrfc_sdata(found)) == found


def test_abap_sends_outbound_kinds_not_the_clients_queued_kind() -> None:
    # 1409196105 for 'T', 1409196101 for 'Q' -- a client submitting a 'Q' unit sends
    # 1409196103 (bgrfc_reference.json); both are read as 'Q'.
    assert bgrfc_unit_type_from_kind(1409196105) == "T"
    assert bgrfc_unit_type_from_kind(1409196101) == "Q"
    assert bgrfc_unit_type_from_kind(1409196103) == "Q"
    assert bgrfc_unit_type_from_kind(0) is None


# --------------------------------------------------------------------------- #
# What saprfclib answered, and what ABAP made of it
# --------------------------------------------------------------------------- #


def test_a_unit_runs_and_is_answered_as_live() -> None:
    server, ran, events = _server()
    answer = server.dispatch_inbound(live("saprfclib", "t_ship"))
    assert answer == live("saprfclib", "t_answer")
    assert ran == ["ours-T"]
    unit_id = dict(_values(live("saprfclib", "t_ship")))["SSTATE"][:16].hex().upper()
    assert events == [("commit", unit_id, "T")]
    # ABAP confirmed it in a second conversation.
    assert server.dispatch_inbound(live("saprfclib", "t_confirm")) == live(
        "saprfclib", "t_confirm_answer"
    )
    assert events[-1] == ("confirm", unit_id, "T")
    assert server._unit_store.get_unit_state(unit_id, "T") is UnitState.CONFIRMED


def test_the_answer_carries_the_reference_servers_values() -> None:
    server, _, _ = _server()
    ours = _values(server.dispatch_inbound(live("reference", "t_ship")))
    assert ours == _values(live("reference", "t_answer"))


def test_a_failing_handler_rolls_back_and_abap_keeps_the_unit() -> None:
    server, _, events = _server()
    server._registry["STFC_CONNECTION"] = (
        descriptors()["STFC_CONNECTION"],
        lambda request: (_ for _ in ()).throw(RuntimeError("unit handler exploded")),
    )
    answer = server.dispatch_inbound(live("saprfclib_handler_failed", "ship"))
    assert answer == live("saprfclib_handler_failed", "answer")
    assert dict(_iter_tlv_records(answer))[0x0402].decode("utf-16-le") == "unit handler exploded"
    assert [e[0] for e in events] == ["rollback"]


def test_an_executed_unit_is_not_run_again_and_abap_confirms_it() -> None:
    server, ran, _ = _server()
    server._on_check_unit = lambda uid, ut: 16
    answer = server.dispatch_inbound(live("saprfclib_already_executed", "ship"))
    assert answer == live("saprfclib_already_executed", "answer")
    assert ran == []


def test_a_resent_unit_runs_once() -> None:
    server, ran, _ = _server()
    server.set_unit_store(InMemoryUnitStore())
    frame = ship_frame(UID, "Q", live_calls())
    first, second = server.dispatch_inbound(frame), server.dispatch_inbound(frame)
    assert first == second
    assert ran == ["bg-T"]
    assert server._unit_store.get_unit_state(UID, "Q") is UnitState.CONFIRMED


def test_the_state_query_reads_unit_id_and_kind() -> None:
    server, _, _ = _server()
    server.dispatch_inbound(ship_frame(UID, "T", live_calls()))
    answer = server.dispatch_inbound(unit_frame("BGRFC_CHECK_UNIT_STATE_SERVER", UID, "T"))
    assert dict(_values(answer))["STATE"] == struct.pack("<i", 22203)
    other = unit_frame("BGRFC_CHECK_UNIT_STATE_SERVER", UID, "Q")
    assert dict(_values(server.dispatch_inbound(other)))["STATE"] == struct.pack("<i", 22206)


# --------------------------------------------------------------------------- #
# Units that cannot be run are refused, not committed
# --------------------------------------------------------------------------- #


def _failure(answer: bytes) -> str:
    return dict(_iter_tlv_records(answer))[0x0402].decode("utf-16-le")


def test_a_unit_without_calls_is_refused() -> None:
    server, _, events = _server()
    assert "no calls" in _failure(server.dispatch_inbound(ship_frame(UID, "T", [])))
    assert events == [("rollback", UID, "T")]


def test_a_call_without_a_handler_fails_the_unit() -> None:
    server, ran, _ = _server()
    calls = [*live_calls(), ("Z_NOT_HERE", b"")]
    answer = server.dispatch_inbound(ship_frame(UID, "T", calls))
    assert _failure(answer) == "Function Z_NOT_HERE not found"
    assert ran == ["bg-T"]
    assert server._unit_store.get_unit_state(UID, "T") is UnitState.IN_PROCESS


def test_execution_stops_at_the_first_failing_call() -> None:
    server, ran, _ = _server()
    calls = [("Z_NOT_HERE", b""), *live_calls()]
    assert "Z_NOT_HERE" in _failure(server.dispatch_inbound(ship_frame(UID, "T", calls)))
    assert ran == []


def _with_sstate(sstate: bytes) -> bytes:
    from ._bgrfc_inbound import _set_values

    return _set_values(live("reference", "t_ship"), {"SSTATE": sstate})


@pytest.mark.parametrize(
    ("frame", "message"),
    [
        (_with_sstate(b"\x01" * 19), "SSTATE is missing or short"),
        (_with_sstate(bytes(16) + struct.pack("<i", 7) + bytes(594)), "unknown UNIT_KIND 7"),
    ],
)
def test_an_unreadable_unit_header_is_refused(frame: bytes, message: str) -> None:
    server, ran, _ = _server()
    assert message in _failure(server.dispatch_inbound(frame))
    assert ran == []


def test_confirm_and_state_need_a_readable_unit() -> None:
    from ._bgrfc_inbound import _set_values

    server, _, events = _server()
    for name in ("BGRFC_DEST_CONFIRM", "BGRFC_CHECK_UNIT_STATE_SERVER"):
        bad = _set_values(unit_frame(name, UID, "T"), {"UNIT_ID": b"\x01" * 15})
        assert "UNIT_ID" in _failure(server.dispatch_inbound(bad))
    assert events == []


# --------------------------------------------------------------------------- #
# SDATA comes from the peer: every length is checked
# --------------------------------------------------------------------------- #


def _sdata() -> bytes:
    return build_bgrfc_sdata(live_calls("reference", "d_ship"))


def test_every_truncation_of_sdata_is_refused() -> None:
    from saprfclib.compress import sapcompress_compress_lzh, sapcompress_decompress

    sdata = _sdata()
    (n,) = struct.unpack_from("<I", sdata, 16)
    plain = sapcompress_decompress(sdata[16:], n)
    for cut in range(0, len(plain), 37):
        short = sdata[:16] + sapcompress_compress_lzh(plain[:cut])
        with pytest.raises(ValueError):
            parse_bgrfc_sdata(short)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b"\x00" + b[1:],  # container header
        lambda b: b[:16] + b"\xff\xff\xff\x7f" + b[20:],  # declared length
        lambda b: b[:30],  # compressed stream cut
        lambda b: b"",
    ],
)
def test_a_damaged_container_is_refused(mutate: Any) -> None:
    with pytest.raises(ValueError):
        parse_bgrfc_sdata(mutate(_sdata()))


def test_a_huge_call_count_is_refused_before_anything_is_read() -> None:
    from saprfclib.compress import sapcompress_compress_lzh, sapcompress_decompress

    sdata = _sdata()
    (n,) = struct.unpack_from("<I", sdata, 16)
    plain = bytearray(sapcompress_decompress(sdata[16:], n))
    plain[0x7C:0x80] = struct.pack(">I", 0xFFFFFFFF)
    with pytest.raises(ValueError, match="declares"):
        parse_bgrfc_sdata(sdata[:16] + sapcompress_compress_lzh(bytes(plain)))
