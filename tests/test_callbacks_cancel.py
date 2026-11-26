# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Server callbacks during a call (#79) and cancelling a call (#82).

Replays tests/golden/framing/callback.json and cancel.json: live exchanges with
ABAP Platform 2025, from the reference client and from saprfclib.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

import saprfclib.connection as connection_module
from saprfclib import CallCancelledError, CommunicationError
from saprfclib.connection import (
    AsyncConnection,
    Connection,
    _build_cancel_frame,
    _callback_failure_tlv,
    _callback_not_found_tlv,
    _is_callback_request,
    _strip_gw_header,
)
from saprfclib.invoke import _iter_tlv_records
from saprfclib.session import SessionState

from ._mocks import AsyncMockTransport, MockTransport
from .test_connection import _handshake_responses

GOLDEN = Path(__file__).parent / "golden" / "framing"
CB = json.loads((GOLDEN / "callback.json").read_text())
CANCEL = json.loads((GOLDEN / "cancel.json").read_text())


def _frames(hexes: list[str]) -> list[bytes]:
    return [bytes.fromhex(h) for h in hexes]


def _async_conn(replies: list[bytes]) -> tuple[AsyncConnection, AsyncMockTransport]:
    sync = Connection(MockTransport(_handshake_responses()))
    sync._handshake(client="001", user="DEVELOPER", passwd="secret")
    transport = AsyncMockTransport(replies)
    conn = AsyncConnection(transport)
    conn._session = sync._session  # READY, with the logon's attributes
    return conn, transport


def _echo(request: dict[str, Any]) -> dict[str, Any]:
    text = request["REQUTEXT"].strip()
    return {"ECHOTEXT": "cb:" + text, "RESPTEXT": "saprfclib callback"}


def _names(frame: bytes) -> list[int]:
    return [t for t, _ in _iter_tlv_records(_strip_gw_header(frame))]


# --------------------------------------------------------------------------- #
# Callbacks
# --------------------------------------------------------------------------- #


def test_a_callback_request_is_told_apart_from_a_reply() -> None:
    served = CB["saprfclib_served"]["server_replies"]
    assert _is_callback_request(_strip_gw_header(bytes.fromhex(served[2])))
    assert not _is_callback_request(_strip_gw_header(bytes.fromhex(served[-1])))


def test_callbacks_are_served_and_answered_as_live() -> None:
    case = CB["saprfclib_served"]
    conn, transport = _async_conn(_frames(case["server_replies"]))
    conn.add_callback("STFC_CONNECTION", _echo)
    result = asyncio.run(
        conn.call("Z_SAPRFCLIB_CB", IV_FM="STFC_CONNECTION", IV_TEXT="hello", IV_TIMES=3)
    )
    assert (result["EV_RC"], result["EV_COUNT"], result["EV_ECHO"]) == (0, 3, "cb:hello 3")
    answers = [f for f in transport.sent if _names(f)[:1] == [0x0500]]
    live = _frames(case["client_answers"])
    assert [_strip_gw_header(a) for a in answers] == [_strip_gw_header(a) for a in live]
    assert conn._session.state is SessionState.READY


def test_an_unknown_function_is_answered_fu_not_found_and_the_call_goes_on() -> None:
    served = CB["saprfclib_served"]["server_replies"]
    case = CB["saprfclib_unknown"]
    conn, transport = _async_conn([bytes.fromhex(served[0]), *_frames(case["server_replies"])])
    result = asyncio.run(
        conn.call("Z_SAPRFCLIB_CB", IV_FM="Z_SAPRFCLIB_NOCB", IV_TEXT="x", IV_TIMES=2)
    )
    assert result["EV_RC"] == 3  # EXCEPTIONS OTHERS in the calling ABAP
    assert _strip_gw_header(transport.sent[-1]) == _strip_gw_header(
        bytes.fromhex(case["client_answer"])
    )
    # Without the 8-byte invoke footer that closes the frame.
    assert _strip_gw_header(transport.sent[-1])[:-8] == _callback_not_found_tlv("Z_SAPRFCLIB_NOCB")
    assert conn._session.state is SessionState.READY


def test_a_failing_handler_ends_the_call_with_a_clear_error() -> None:
    served = CB["saprfclib_served"]["server_replies"]
    case = CB["saprfclib_handler_failed"]
    replies = [
        bytes.fromhex(served[0]),
        bytes.fromhex(served[1]),
        bytes.fromhex(case["callback_request"]),
        bytes.fromhex(case["then"]),
    ]
    conn, transport = _async_conn(replies)

    def boom(request: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("handler exploded")

    conn.add_callback("STFC_CONNECTION", boom)
    with pytest.raises(CommunicationError, match="STFC_CONNECTION raised"):
        asyncio.run(conn.call("Z_SAPRFCLIB_CB", IV_FM="STFC_CONNECTION", IV_TEXT="x", IV_TIMES=1))
    assert conn._session.state is SessionState.BROKEN
    answer = dict(_iter_tlv_records(_strip_gw_header(transport.sent[-1])))
    assert "handler exploded" in answer[0x0402].decode("utf-16-le")
    assert 0x0403 not in answer  # as the reference server's answer to a failing handler


def test_the_failure_answer_has_the_reference_servers_records() -> None:
    ref = _names(bytes.fromhex(CB["reference_server_handler_failed"]["answer"]))
    sync = Connection(MockTransport(_handshake_responses()))
    sync._handshake(client="001", user="DEVELOPER", passwd="secret")
    ours = [t for t, _ in _iter_tlv_records(_callback_failure_tlv(sync._session, "m"))]
    # The reference adds its 0x0667 timing records; the rest is the same, in order.
    assert ours == [t for t in ref if t != 0x0667]


def test_callbacks_per_call_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    case = CB["saprfclib_served"]
    monkeypatch.setattr(connection_module, "_MAX_CALLBACKS_PER_CALL", 2)
    conn, _ = _async_conn(_frames(case["server_replies"]))
    conn.add_callback("STFC_CONNECTION", _echo)
    with pytest.raises(CommunicationError, match="more than 2 times"):
        asyncio.run(conn.call("Z_SAPRFCLIB_CB", IV_FM="STFC_CONNECTION", IV_TEXT="h", IV_TIMES=3))


def test_callbacks_and_cancel_need_a_classic_tcp_connection() -> None:
    conn = Connection(MockTransport([]))
    with pytest.raises(NotImplementedError):
        conn.add_callback("STFC_CONNECTION", _echo)
    with pytest.raises(NotImplementedError):
        conn.cancel()


# --------------------------------------------------------------------------- #
# Cancel
# --------------------------------------------------------------------------- #


def test_the_cancel_frame_is_the_reference_clients() -> None:
    for frames in (CANCEL["reference"], CANCEL["saprfclib"]):
        sent = bytes.fromhex(frames[0]["frame"])
        tail = int.from_bytes(sent[78:80], "big")
        assert _build_cancel_frame(sent[40:48], tail) == sent
        assert bytes.fromhex(frames[1]["frame"])[:2] == b"\x06\xd6"


class _CancellableTransport(AsyncMockTransport):
    """Answers the call only with the gateway's cancel acknowledgement, once asked."""

    def __init__(self, replies: list[bytes]) -> None:
        super().__init__(replies)
        self.cancelled = asyncio.Event()

    async def send_message(self, payload: bytes) -> None:
        await super().send_message(payload)
        if payload[:2] == b"\x06\xd5":
            self.cancelled.set()

    async def recv_message(self) -> bytes:
        if self._responses:
            return await super().recv_message()
        await self.cancelled.wait()
        return bytes.fromhex(CANCEL["reference"][1]["frame"])


def test_cancel_raises_in_the_call_and_retires_the_connection() -> None:
    served = CB["saprfclib_served"]["server_replies"]

    async def main() -> tuple[bool, bool, BaseException | None, AsyncConnection]:
        sync = Connection(MockTransport(_handshake_responses()))
        sync._handshake(client="001", user="DEVELOPER", passwd="secret")
        transport = _CancellableTransport([bytes.fromhex(served[0])])
        conn = AsyncConnection(transport)
        conn._session = sync._session
        assert await conn.cancel() is False  # nothing in flight
        task = asyncio.create_task(
            conn.call("Z_SAPRFCLIB_CB", IV_FM="STFC_CONNECTION", IV_TEXT="x", IV_TIMES=1)
        )
        while conn._in_flight is None:
            await asyncio.sleep(0)
        first = await conn.cancel()
        second = await conn.cancel()
        try:
            await task
            err = None
        except BaseException as exc:  # noqa: BLE001
            err = exc
        return first, second, err, conn

    first, second, err, conn = asyncio.run(main())
    assert (first, second) == (True, False)
    assert isinstance(err, CallCancelledError)
    assert err.func_name == "Z_SAPRFCLIB_CB"
    assert conn._session.state is SessionState.BROKEN


# --------------------------------------------------------------------------- #
# RfcServer answers a call it cannot run as the reference SDK's server does
# --------------------------------------------------------------------------- #

_REF_HEADER = {0x0101, 0x0103, 0x0106, 0x0007, 0x0011, 0x0012, 0x0013, 0x0130, 0x0667}


def _server() -> Any:
    from saprfclib.server import RfcServer

    return RfcServer({"program_id": "ZTEST", "gwhost": "gw.example", "gwserv": "sapgw00"})


@pytest.mark.parametrize(
    ("ours", "reference", "message", "key"),
    [
        (
            "saprfclib_server_not_found",
            "reference_server_not_found",
            "Function STFC_CONNECTION not found",
            "RFC_NOT_FOUND",
        ),
        (
            "saprfclib_server_handler_failed",
            "reference_server_handler_failed",
            "handler exploded",
            None,
        ),
    ],
)
def test_rfc_server_failures_take_the_reference_servers_form(
    ours: str, reference: str, message: str, key: str | None
) -> None:
    built = _server()._build_system_failure(message, key=key)
    live = bytes.fromhex(CB[ours]["answer"])[80:]
    assert live[: len(built)] == built  # what went to ABAP, which read it (callback.json)
    ref = [t for t in _names(bytes.fromhex(CB[reference]["answer"])) if t not in _REF_HEADER]
    assert [t for t, _ in _iter_tlv_records(built)] == ref
    assert 0x0420 not in dict(_iter_tlv_records(built))
