# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The client against a scripted peer on a real socket (#87), and the tRFC retry (#75).

Every reply the peer sends is a captured frame (handshake fixtures, the kernel 916
logon reply, the RFCPING reply, the tRFC submit reply); only its delivery is staged.
Each damaged delivery must end in a typed error and a connection that refuses
further use, never a hang and never a silent success.
"""

from __future__ import annotations

import json

import pytest

import saprfclib
from saprfclib.exceptions import CommunicationError, RetryExhausted
from saprfclib.session import SessionState
from saprfclib.stores import InMemoryTidStore
from tests._trfc_fixture import DESCS
from tests.conftest import GOLDEN_ROOT, load_fixture
from tests.support.scripted_peer import (
    MAX_BYTES,
    MAX_DELAY,
    MAX_STEPS,
    Close,
    Delay,
    Expect,
    HalfClose,
    Reply,
    Reset,
    ScriptedPeer,
)

_H = GOLDEN_ROOT / "handshake"
NI_VERSION = load_fixture(_H, "ni_version_response").payload_bytes
GW_CONNECT = load_fixture(_H, "gw_connect_response").payload_bytes
GW_DONE = load_fixture(_H, "gw_done_server").payload_bytes
LOGON = (GOLDEN_ROOT / "framing" / "logon_reply_kernel916.bin").read_bytes()[4:]
PING = (GOLDEN_ROOT / "framing" / "rfcping_response.bin").read_bytes()
_TRFC = json.loads((GOLDEN_ROOT / "trfc" / "trfc_reference.json").read_text(encoding="utf-8"))
SUBMIT_REPLY = [bytes.fromhex(h) for h in _TRFC["trfc"]["submit"]["reply"]]

# The client's side of the handshake, as captured: NI version, GW connect, GW info
# plus GW done (one reply for the two), logon.
HANDSHAKE = [
    Expect(),
    Reply(NI_VERSION),
    Expect(),
    Reply(GW_CONNECT),
    Expect(),
    Expect(),
    Reply(GW_DONE),
    Expect(),
    Reply(LOGON),
]
TID = "ABCDEF1234567890ABCDEF12"


def _connect(peer: ScriptedPeer, **kwargs: object) -> saprfclib.connection.Connection:
    kwargs.setdefault("read_timeout", 5)
    return saprfclib.connect(
        ashost="127.0.0.1",
        sysnr="00",
        port=peer.port,
        client="001",
        user="USER",
        passwd="secret",
        **kwargs,  # type: ignore[arg-type]
    )


def _assert_unusable(conn: saprfclib.connection.Connection) -> None:
    """After a damaged reply the connection must refuse, not read leftovers."""
    assert conn._session.state is SessionState.BROKEN
    with pytest.raises(ValueError, match="connection is unusable"):
        conn.ping()


# --------------------------------------------------------------------------- #
# The harness itself
# --------------------------------------------------------------------------- #


def test_the_peer_records_the_handshake_and_a_call() -> None:
    with ScriptedPeer([*HANDSHAKE, Expect(), Reply(PING)]) as peer:
        conn = _connect(peer)
        assert conn.get_connection_attributes().kernel_rel == "916"
        conn.ping()
        conn.close()
    frames = peer.connections[0].received
    assert len(frames) == 6  # NI version, GW connect, GW info, GW done, logon, RFCPING
    assert b"R\x00F\x00C\x00P\x00I\x00N\x00G\x00" in frames[-1]
    assert peer.connections[0].closed_by_client


@pytest.mark.parametrize(
    "script",
    [
        [Expect()] * (MAX_STEPS + 1),
        [Delay(MAX_DELAY + 1)],
        [Reply(b"x", delay=-1)],
        [Reply(b"\x00" * MAX_BYTES)],
    ],
    ids=["too-many-steps", "delay-too-long", "negative-delay", "too-many-bytes"],
)
def test_scripts_are_bounded(script: list) -> None:
    with pytest.raises(ValueError):
        ScriptedPeer(script)


def test_a_peer_that_never_sees_its_client_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.support import scripted_peer

    monkeypatch.setattr(scripted_peer, "IO_TIMEOUT", 0.2)
    peer = ScriptedPeer([Expect()])
    peer._server.settimeout(0.2)
    peer.__enter__()
    with pytest.raises(AssertionError, match="scripted peer failed"):
        peer.close()


# --------------------------------------------------------------------------- #
# Damaged deliveries the client must survive
# --------------------------------------------------------------------------- #


def test_a_reply_split_into_single_bytes_is_reassembled() -> None:
    script = [*HANDSHAKE[:-1], Reply(LOGON, chunks=(1, 3, 2, 7)), Expect()]
    script.append(Reply(PING, chunks=(1,) * 40, pause=0.001))
    with ScriptedPeer(script) as peer:
        conn = _connect(peer)
        conn.ping()
        conn.close()


def test_two_replies_in_one_write_are_split_at_the_frame_boundary() -> None:
    script = [*HANDSHAKE[:-1], Reply(LOGON, coalesce=True), Reply(PING), Expect()]
    with ScriptedPeer(script) as peer:
        conn = _connect(peer)
        conn.ping()  # its reply is already in the socket buffer, behind the logon reply
        conn.close()


@pytest.mark.parametrize(
    "steps",
    [
        [Reply(PING, truncate=50)],
        [Reset()],
        [HalfClose(), Delay(0.5)],
        [Reply(PING, length_delta=100), Close()],
        [Close()],
    ],
    ids=["truncated", "reset", "half-close", "length-too-long", "closed"],
)
def test_a_damaged_reply_raises_and_retires_the_connection(steps: list) -> None:
    with ScriptedPeer([*HANDSHAKE, Expect(), *steps]) as peer:
        conn = _connect(peer)
        with pytest.raises(CommunicationError):
            conn.ping()
        _assert_unusable(conn)
        conn.close()


def test_a_declared_length_over_the_cap_is_refused_before_reading() -> None:
    with ScriptedPeer(
        [*HANDSHAKE, Expect(), Reply(PING, length_override=200 * 1024 * 1024)]
    ) as peer:
        conn = _connect(peer)
        with pytest.raises(ValueError, match="exceeds cap"):
            conn.ping()
        _assert_unusable(conn)
        conn.close()


def test_a_reply_slower_than_the_read_timeout_raises() -> None:
    with ScriptedPeer([*HANDSHAKE, Expect(), Reply(PING, delay=1.0)]) as peer:
        conn = _connect(peer, read_timeout=0.3)
        with pytest.raises(CommunicationError):
            conn.ping()
        _assert_unusable(conn)
        conn.close()


# --------------------------------------------------------------------------- #
# #75: a transactional retry goes over a new connection, with the same TID
# --------------------------------------------------------------------------- #


def _serve_metadata(conn: saprfclib.connection.Connection) -> None:
    async def _desc_for(name: str):  # type: ignore[no-untyped-def]
        return DESCS[name.upper()]

    conn._async_conn._desc_for = _desc_for  # type: ignore[union-attr,method-assign]


@pytest.mark.parametrize(
    "failure",
    [[Reset()], [Reply(SUBMIT_REPLY[0], truncate=40)], [HalfClose(), Delay(0.5)]],
    ids=["reset", "truncated-reply", "half-close"],
)
def test_a_trfc_retry_reconnects_and_resends_the_same_tid(failure: list) -> None:
    first = [*HANDSHAKE, Expect(), *failure]
    second = [*HANDSHAKE, Expect(), *[Reply(f) for f in SUBMIT_REPLY]]
    with ScriptedPeer(first, second) as peer:
        conn = _connect(peer, max_retries=1, retry_delay=0.0)
        _serve_metadata(conn)
        conn.call_transactional("STFC_CONNECTION", tid=TID, REQUTEXT="x")
        assert conn._session.state is SessionState.READY
        conn.close()
    assert len(peer.connections) == 2, "the retry must open a new connection"
    tid = TID.encode("utf-16-le")
    first_submit = peer.connections[0].received[-1]
    second = peer.connections[1].received
    assert tid in first_submit
    # The second connection ran the whole handshake before the resend...
    assert len(second) == 6
    # ...and resent the same TID, never on the failed stream.
    assert tid in second[-1]


def test_exhausted_retries_park_the_call_and_retire_the_connection() -> None:
    failing = [*HANDSHAKE, Expect(), Reset()]
    store = InMemoryTidStore()
    with ScriptedPeer(failing, failing) as peer:
        conn = _connect(peer, max_retries=1, retry_delay=0.0, tid_store=store)
        _serve_metadata(conn)
        with pytest.raises(RetryExhausted):
            conn.call_transactional("STFC_CONNECTION", tid=TID, REQUTEXT="x")
        assert conn._session.state is SessionState.BROKEN
        conn.close()
    assert len(peer.connections) == 2
    assert store.get_parked(TID) is not None


def test_a_reconnect_that_cannot_reach_the_server_counts_as_a_failed_attempt() -> None:
    """Only one script: after it, the peer refuses connections, so the reconnect fails."""
    store = InMemoryTidStore()
    with ScriptedPeer([*HANDSHAKE, Expect(), Reset()]) as peer:
        conn = _connect(peer, max_retries=1, retry_delay=0.0, tid_store=store)
        _serve_metadata(conn)
        with pytest.raises(RetryExhausted) as info:
            conn.call_transactional("STFC_CONNECTION", tid=TID, REQUTEXT="x")
        assert "reconnect failed" in str(info.value.cause)
        assert conn._session.state is SessionState.BROKEN
        conn.close()
    assert len(peer.connections) == 1
    assert store.get_parked(TID) is not None


# --------------------------------------------------------------------------- #
# #75, sync path (connections not on the async core, e.g. SNC): no retry, but a
# failed exchange must retire the session instead of handing it back READY.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("method", ["call_transactional", "confirm_tid"])
def test_a_sync_transactional_failure_retires_the_session(
    method: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from saprfclib.connection import Connection
    from tests._mocks import MockTransport
    from tests._trfc_fixture import use_fixture_metadata

    conn = Connection(MockTransport([]))  # no reply: the read hits EOF
    use_fixture_metadata(monkeypatch)
    conn._session._state = SessionState.READY
    with pytest.raises(CommunicationError):
        if method == "call_transactional":
            conn.call_transactional("STFC_CONNECTION", tid=TID, REQUTEXT="x")
        else:
            conn.confirm_tid(TID)
    assert conn._session.state is SessionState.BROKEN
