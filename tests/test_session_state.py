# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Server context reset (#68) and the BAPI transaction helper (#83).

The reset is replayed from tests/golden/framing/reset_server_context.json, the
reference client's request and the server's reply. What it does to ABAP session
state was checked live with a probe module that keeps a value in its function group
(docs/protocol/framing.md); the integration test at the end repeats that check where
the module exists.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import pytest

import saprfclib
from saprfclib.connection import AsyncConnection, Connection
from saprfclib.exceptions import AbapApplicationError
from saprfclib.session import SessionState
from tests._mocks import AsyncMockTransport, MockTransport
from tests.conftest import GOLDEN_ROOT
from tests.support.scripted_peer import Expect, Reply, ScriptedPeer
from tests.test_scripted_peer import HANDSHAKE, PING, _connect

FX = json.loads((GOLDEN_ROOT / "framing" / "reset_server_context.json").read_text(encoding="utf-8"))
RESET_REQUEST = bytes.fromhex(FX["request_hex"])
RESET_REPLY = bytes.fromhex(FX["reply_hex"])
# The TLV body starts at 80: the 76-byte GW header, then the 4-byte RFC marker, whose
# last byte is the gateway-assigned connection index (3 on the captured connection).
_BODY = 80
_CONN_IDX = RESET_REQUEST[79]

# --------------------------------------------------------------------------- #
# reset_server_context
# --------------------------------------------------------------------------- #


def test_the_reset_request_body_matches_the_reference_client() -> None:
    frame = Connection._build_invoke_frame(
        b"        ", Connection._reset_request_tlv(), conn_idx=_CONN_IDX
    )
    assert frame[76:] == RESET_REQUEST[76:]  # marker with the same index, body, footer
    assert len(frame) == len(RESET_REQUEST)


def test_reset_goes_on_the_wire_without_a_metadata_lookup_and_the_connection_stays_usable() -> None:
    script = [*HANDSHAKE, Expect(), Reply(RESET_REPLY), Expect(), Reply(PING)]
    with ScriptedPeer(script) as peer:
        conn = _connect(peer)
        conn.reset_server_context()
        assert conn._session.state is SessionState.READY
        conn.ping()
        conn.close()
    frames = peer.connections[0].received
    assert len(frames) == 7  # handshake (5), the reset, the ping: no metadata round trip
    assert frames[5][_BODY:] == RESET_REQUEST[_BODY:]


def test_a_reset_whose_reply_is_lost_retires_the_connection() -> None:
    from saprfclib.exceptions import CommunicationError
    from tests.support.scripted_peer import Reset

    with ScriptedPeer([*HANDSHAKE, Expect(), Reset()]) as peer:
        conn = _connect(peer)
        with pytest.raises(CommunicationError):
            conn.reset_server_context()
        assert conn._session.state is SessionState.BROKEN
        conn.close()


async def test_the_async_reset_sends_the_same_request() -> None:
    transport = AsyncMockTransport([RESET_REPLY])
    conn = AsyncConnection(transport)  # type: ignore[arg-type]
    conn._session._state = SessionState.READY
    await conn.reset_server_context()
    assert transport.sent[0][_BODY:] == RESET_REQUEST[_BODY:]
    assert conn._session.state is SessionState.READY


def test_reset_is_refused_over_websocket_rfc(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = Connection(MockTransport([]))
    monkeypatch.setattr(conn, "_is_ws", lambda: True)
    with pytest.raises(NotImplementedError, match="WebSocket"):
        conn.reset_server_context()


# --------------------------------------------------------------------------- #
# ConnectionPool(reset_on_release=True)
# --------------------------------------------------------------------------- #


class _Conn:
    def __init__(self, *, fail_reset: bool = False) -> None:
        self.resets = 0
        self.closed = False
        self.fail_reset = fail_reset

    def ping(self) -> bool:
        return True

    def reset_server_context(self) -> None:
        self.resets += 1
        if self.fail_reset:
            raise RuntimeError("reset refused")

    def close(self) -> None:
        self.closed = True


def _pool(monkeypatch: pytest.MonkeyPatch, conns: list[_Conn], **kwargs: Any) -> Any:
    from saprfclib import pool as poolmod

    it = iter(conns)
    monkeypatch.setattr(poolmod._connection, "connect", lambda **_: next(it))
    return poolmod.ConnectionPool({}, min_size=0, max_size=2, **kwargs)


def test_the_pool_resets_a_connection_before_lending_it_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = _Conn()
    pool = _pool(monkeypatch, [c], reset_on_release=True)
    with pool.acquire() as first:
        assert first is c
    assert c.resets == 1
    with pool.acquire() as again:
        assert again is c  # reused, not replaced
    assert c.resets == 2
    pool.close()


def test_a_connection_whose_reset_fails_is_discarded(monkeypatch: pytest.MonkeyPatch) -> None:
    bad, good = _Conn(fail_reset=True), _Conn()
    pool = _pool(monkeypatch, [bad, good], reset_on_release=True)
    with pool.acquire() as first:
        assert first is bad
    assert bad.closed and pool.idle == 0 and pool.metrics.discards == 1
    with pool.acquire() as second:
        assert second is good
    pool.close()


def test_without_the_option_nothing_is_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _Conn()
    pool = _pool(monkeypatch, [c])
    with pool.acquire():
        pass
    assert c.resets == 0
    pool.close()


async def test_the_async_pool_resets_too(monkeypatch: pytest.MonkeyPatch) -> None:
    from saprfclib import pool as poolmod

    class _AConn(_Conn):
        async def ping(self) -> bool:  # type: ignore[override]
            return True

        async def reset_server_context(self) -> None:  # type: ignore[override]
            _Conn.reset_server_context(self)

        async def close(self) -> None:  # type: ignore[override]
            self.closed = True

    c = _AConn()

    async def _open(**_: Any) -> _AConn:
        return c

    monkeypatch.setattr(poolmod._connection, "connect_async", _open)
    pool = poolmod.AsyncConnectionPool({}, min_size=0, max_size=1, reset_on_release=True)
    async with pool.acquire():
        pass
    assert c.resets == 1
    await pool.close()


# --------------------------------------------------------------------------- #
# conn.transaction()
# --------------------------------------------------------------------------- #

_OK = {"RETURN": {"TYPE": "", "ID": "", "NUMBER": "000", "MESSAGE": ""}}


def _recording(conn: Any, replies: dict[str, Any] | None = None) -> list[tuple[str, dict]]:
    calls: list[tuple[str, dict]] = []

    def call(name: str, **params: Any) -> Any:
        calls.append((name, params))
        reply = (replies or {}).get(name, _OK)
        if isinstance(reply, BaseException):
            raise reply
        return reply

    conn.call = call
    return calls


def test_a_clean_block_commits_and_waits() -> None:
    conn = Connection(MockTransport([]))
    calls = _recording(conn)
    with conn.transaction() as c:
        c.call("BAPI_SOMETHING", X=1)
    assert calls == [("BAPI_SOMETHING", {"X": 1}), ("BAPI_TRANSACTION_COMMIT", {"WAIT": "X"})]


def test_wait_false_commits_without_waiting() -> None:
    conn = Connection(MockTransport([]))
    calls = _recording(conn)
    with conn.transaction(wait=False):
        pass
    assert calls == [("BAPI_TRANSACTION_COMMIT", {"WAIT": ""})]


def test_a_failing_block_rolls_back_and_reraises() -> None:
    conn = Connection(MockTransport([]))
    calls = _recording(conn)
    with pytest.raises(KeyError):
        with conn.transaction():
            raise KeyError("boom")
    assert calls == [("BAPI_TRANSACTION_ROLLBACK", {})]


def test_an_error_in_the_commit_return_raises() -> None:
    conn = Connection(MockTransport([]))
    ret = {"RETURN": {"TYPE": "E", "ID": "ZFI", "NUMBER": "042", "MESSAGE": "commit failed"}}
    _recording(conn, {"BAPI_TRANSACTION_COMMIT": ret})
    with pytest.raises(AbapApplicationError) as info:
        with conn.transaction():
            pass
    assert info.value.msg_class == "ZFI" and info.value.msg_number == "042"


def test_a_failed_rollback_does_not_hide_the_original_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    conn = Connection(MockTransport([]))
    _recording(conn, {"BAPI_TRANSACTION_ROLLBACK": RuntimeError("rollback broke")})
    with caplog.at_level(logging.WARNING), pytest.raises(KeyError):
        with conn.transaction():
            raise KeyError("boom")
    assert "rollback after a failed block also failed" in caplog.text


def test_no_rollback_over_a_retired_connection() -> None:
    conn = Connection(MockTransport([]))
    calls = _recording(conn)
    with pytest.raises(ValueError):
        with conn.transaction():
            conn._session.mark_broken("test")
            raise ValueError("transport gone")
    assert calls == []


async def test_the_async_transaction_commits_and_rolls_back() -> None:
    conn = AsyncConnection(AsyncMockTransport([]))  # type: ignore[arg-type]
    calls: list[str] = []

    async def call(name: str, **params: Any) -> Any:
        calls.append(name)
        return _OK

    conn.call = call  # type: ignore[method-assign]
    async with conn.transaction():
        pass
    with pytest.raises(KeyError):
        async with conn.transaction():
            raise KeyError("boom")
    assert calls == ["BAPI_TRANSACTION_COMMIT", "BAPI_TRANSACTION_ROLLBACK"]


# --------------------------------------------------------------------------- #
# Live: the reset clears function-group state, which persists again afterwards
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("SAPRFC_ASHOST"), reason="needs a live SAP system")
def test_live_reset_clears_session_state() -> None:
    conn = saprfclib.connect(
        ashost=os.environ["SAPRFC_ASHOST"],
        sysnr=os.environ.get("SAPRFC_SYSNR", "00"),
        client=os.environ["SAPRFC_CLIENT"],
        user=os.environ["SAPRFC_USER"],
        passwd=os.environ["SAPRFC_PASSWD"],
    )
    try:
        try:
            saprfclib.get_function_desc(conn, "Z_SAPRFCLIB_CTX")
        except Exception:
            pytest.skip("probe module Z_SAPRFCLIB_CTX is not on this system")

        def get() -> str:
            return conn.call("Z_SAPRFCLIB_CTX", IV_OP="G")["EV_VAL"].strip()

        conn.call("Z_SAPRFCLIB_CTX", IV_OP="S", IV_VAL="AAA")
        assert get() == "AAA"
        conn.reset_server_context()
        assert get() == ""
        conn.call("Z_SAPRFCLIB_CTX", IV_OP="S", IV_VAL="BBB")
        assert get() == "BBB"
    finally:
        conn.close()
