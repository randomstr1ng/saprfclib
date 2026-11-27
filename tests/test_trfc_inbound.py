# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""RfcServer receives tRFC and qRFC LUWs as ABAP sends them (#122).

Replays tests/golden/trfc/trfc_inbound.json: ABAP sending LUWs through a registered
destination, first to a server built on the NW RFC SDK with its transaction
handlers, then to saprfclib's, with what ABAP did with each answer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from saprfclib.invoke import _iter_tlv_records
from saprfclib.server import RfcServer, _extract_name_value_pairs, _rows, _trfc_luw

from ._trfc_fixture import SHIP, STFC_CONNECTION, forged_inbound_trfc, trfc_descriptors

FX = json.loads((Path(__file__).parent / "golden" / "trfc" / "trfc_inbound.json").read_text())


def _frame(side: str, case: str, key: str) -> bytes:
    return bytes.fromhex(FX[side][case][key])


def _server() -> tuple[RfcServer, list[str], list[tuple[str, str]]]:
    server = RfcServer({"program_id": "ZTEST", "gwhost": "gw.example", "gwserv": "sapgw00"})
    server.set_trfc_descriptors(*trfc_descriptors())
    ran: list[str] = []
    events: list[tuple[str, str]] = []

    @server.function("STFC_CONNECTION", STFC_CONNECTION)
    def _stfc(request: dict[str, Any]) -> dict[str, Any]:
        ran.append(request["REQUTEXT"])
        return {}

    def note(name: str) -> Any:
        return lambda tid: events.append((name, tid))

    server.install_transaction_handlers(
        on_commit=note("commit"), on_rollback=note("rollback"), on_confirm=note("confirm")
    )
    return server, ran, events


def _state(side: str, case: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    raw = dict(_extract_name_value_pairs(_frame(side, case, "ship"), row_counts_out=counts))
    field = next(f for f in SHIP.parameters if f.name == "STATE")
    return _rows(raw["STATE"], field, counts["STATE"])


# --------------------------------------------------------------------------- #
# What ABAP sends
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("case", "calls"),
    [
        ("one_call", ["STFC_CONNECTION"]),
        ("three_calls", ["STFC_CONNECTION", "Z_SAPRFCLIB_DEEP2", "STFC_CONNECTION"]),
        ("queued", ["STFC_CONNECTION"]),
    ],
)
def test_abap_sends_the_luw_in_state_and_data_rows(case: str, calls: list[str]) -> None:
    tid, found = _trfc_luw(_frame("reference", case, "ship"), SHIP)
    assert len(tid) == 24
    assert [name for name, _ in found] == calls
    # Each record is the call itself: its 0x0102 names the function its STATE row does.
    for name, record in found:
        names = [v.decode("utf-16-le") for t, v in _iter_tlv_records(record) if t == 0x0102]
        assert names == [name]


def test_state_rows_are_compressed_and_restored_to_full_width() -> None:
    # 0x0304 records of 955 bytes where ARFCRSTATE is 972: the row is cut after its
    # last byte, 0x00, and restored by repeating it. HASH is RAW(40) at 932.
    raw = bytes.fromhex(FX["reference"]["one_call"]["ship"])
    records = [v for t, v in _iter_tlv_records(raw) if t == 0x0304]
    assert {len(r) for r in records} == {955} and records[0][-1] == 0
    row = _state("reference", "one_call")[0]
    assert row["HASH"][:23] == records[0][932:] and row["HASH"][23:] == bytes(17)
    assert row["ARFCDEST"].strip() == "ZSAPRFCLIB_BXML"
    assert row["ARFCFNAM"].strip() == "STFC_CONNECTION"


def test_a_queued_luw_names_its_queue_in_arfcreserv() -> None:
    queued = _state("reference", "queued")[0]["ARFCRESERV"]
    assert queued[44:45] == "O"
    assert queued[45:].split()[0] == "ZSAPRFCLIB_OQ"
    assert _state("reference", "one_call")[0]["ARFCRESERV"][44:45] == " "


# --------------------------------------------------------------------------- #
# What saprfclib answered, and what ABAP made of it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", ["one_call", "queued"])
def test_a_luw_runs_and_is_answered_as_live(case: str) -> None:
    server, ran, events = _server()
    assert server.dispatch_inbound(_frame("saprfclib", case, "ship")) == _frame(
        "saprfclib", case, "answer"
    )
    assert ran == [f"ours-{'C' if case == 'one_call' else 'K'}"]
    tid = _trfc_luw(_frame("saprfclib", case, "ship"), SHIP)[0]
    assert events == [("commit", tid)]
    assert server._tid_store.is_executed(tid)
    # ABAP confirmed it.
    assert server.dispatch_inbound(_frame("saprfclib", case, "confirm")) == _frame(
        "saprfclib", case, "confirm_answer"
    )
    assert events[-1] == ("confirm", tid)


def test_the_answer_carries_the_tables_the_reference_answers_with() -> None:
    server, _, _ = _server()
    ours = server.dispatch_inbound(_frame("reference", "one_call", "ship"))
    ref = _frame("reference", "one_call", "answer")

    def tables(frame: bytes) -> dict[bytes, bytes]:
        recs = list(_iter_tlv_records(frame))
        return {v: recs[i + 1][1] for i, (t, v) in enumerate(recs[:-1]) if t == 0x0301}

    assert tables(ours) == tables(ref)


def test_a_failing_handler_rolls_back_and_abap_keeps_the_tid() -> None:
    server, _, events = _server()
    server._registry["STFC_CONNECTION"] = (
        STFC_CONNECTION,
        lambda request: (_ for _ in ()).throw(RuntimeError("unit handler exploded")),
    )
    answer = server.dispatch_inbound(_frame("saprfclib", "handler_failed", "ship"))
    assert answer == _frame("saprfclib", "handler_failed", "answer")
    assert dict(_iter_tlv_records(answer))[0x0402].decode("utf-16-le") == "unit handler exploded"
    tid = _trfc_luw(_frame("saprfclib", "handler_failed", "ship"), SHIP)[0]
    assert events == [("rollback", tid)]
    assert not server._tid_store.is_executed(tid)
    # ABAP still confirms, with ERRORSTATUS 1, in a new conversation.
    assert server.dispatch_inbound(_frame("saprfclib", "handler_failed", "confirm")) == _frame(
        "saprfclib", "handler_failed", "confirm_answer"
    )


def test_an_executed_tid_is_not_run_again_and_abap_confirms_it() -> None:
    server, ran, _ = _server()
    server._on_check_transaction = lambda tid: 16
    answer = server.dispatch_inbound(_frame("saprfclib", "already_executed", "ship"))
    assert answer == _frame("saprfclib", "already_executed", "answer")
    assert ran == []


def test_three_calls_run_in_order() -> None:
    server, ran, _ = _server()
    deep: list[dict[str, Any]] = []
    server.function("Z_SAPRFCLIB_DEEP2")(lambda request: deep.append(request) or {})
    server.dispatch_inbound(_frame("reference", "three_calls", "ship"))
    assert ran == ["ref-M", "ref-M-2"]
    assert deep == [{}]  # no descriptor registered for it: called without values


# --------------------------------------------------------------------------- #
# A LUW that cannot be read or run is refused, not committed
# --------------------------------------------------------------------------- #


def _failure(answer: bytes) -> str:
    return dict(_iter_tlv_records(answer))[0x0402].decode("utf-16-le")


def test_without_descriptors_the_luw_is_refused_with_a_pointer() -> None:
    server = RfcServer({"program_id": "ZTEST", "gwhost": "gw.example", "gwserv": "sapgw00"})
    answer = server.dispatch_inbound(_frame("reference", "one_call", "ship"))
    assert "set_trfc_descriptors" in _failure(answer)
    confirm = server.dispatch_inbound(_frame("reference", "one_call", "confirm"))
    assert "set_trfc_descriptors" in _failure(confirm)


def test_execution_stops_at_the_first_failing_call() -> None:
    server, ran, events = _server()
    frame = forged_inbound_trfc("ABCDEF1234567890ABCDEF12", "Z_NOT_HERE", "STFC_CONNECTION")
    assert "Z_NOT_HERE" in _failure(server.dispatch_inbound(frame))
    assert ran == []
    assert events == [("rollback", "ABCDEF1234567890ABCDEF12")]


def test_rows_of_two_tids_are_refused() -> None:
    server, ran, _ = _server()
    one = forged_inbound_trfc("ABCDEF1234567890ABCDEF12", "STFC_CONNECTION")
    # The DATA rows keep the first TID, the STATE row gets another.
    tid = "ABCDEF1234567890ABCDEF12".encode("utf-16-le")
    at = one.rindex(tid)
    mixed = one[:at] + "ZZZZZZ1234567890ABCDEF12".encode("utf-16-le") + one[at + len(tid) :]
    assert "TIDs" in _failure(server.dispatch_inbound(mixed))
    assert ran == []


def test_a_confirm_without_a_readable_callid_is_refused() -> None:
    server, _, events = _server()
    bad = _frame("reference", "one_call", "confirm").replace(
        "C6336409".encode("utf-16-le"), "C63364.9".encode("utf-16-le")
    )
    assert "ARFC_DEST_CONFIRM" in _failure(server.dispatch_inbound(bad))
    assert events == []


def test_a_compressed_row_is_restored_by_repeating_its_last_byte() -> None:
    from saprfclib.invoke import _expand_compressed_row

    assert _expand_compressed_row(b"ab\x00", 6, "T") == b"ab\x00\x00\x00\x00"
    assert _expand_compressed_row(b"a b ", 7, "T") == b"a b    "
    assert _expand_compressed_row(b"full", 4, "T") == b"full"  # nothing to restore
    with pytest.raises(ValueError, match="empty compressed row"):
        _expand_compressed_row(b"", 4, "T")
