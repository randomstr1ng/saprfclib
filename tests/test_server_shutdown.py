# SPDX-License-Identifier: MPL-2.0
"""RfcServer shutdown: 06d0 is the last frame, sent by the serve thread (issue #58).

The NW RFC SDK sends 06d0 once, at shutdown, immediately before FIN — golden fixture
server_listen_end.bin. stop() runs on another thread, so it only shuts down reads;
the serve thread, which owns the socket, sends 06d0 and closes.
"""

from __future__ import annotations

import queue
import threading
from pathlib import Path

import pytest

from saprfclib import transport as transport_mod
from saprfclib.server import RfcServer

_GOLDEN = Path(__file__).parent / "golden" / "framing"


def _payload(name: str) -> bytes:
    return (_GOLDEN / f"{name}.bin").read_bytes()[4:]


class _ScriptedTransport:
    """Replays gateway frames, then blocks in recv until reads are shut down."""

    def __init__(self, frames: list[bytes], *, eof_after_script: bool = False) -> None:
        self._inbox: queue.Queue[bytes | None] = queue.Queue()
        for f in frames:
            self._inbox.put(f)
        if eof_after_script:
            self._inbox.put(None)
        self.sent: list[bytes] = []
        self.events: list[str] = []
        self.waiting = threading.Event()

    local_address = ("10.0.0.1", 40000)

    def send_message(self, payload: bytes) -> None:
        self.sent.append(payload)
        self.events.append("send")

    def recv_message(self) -> bytes:
        if self._inbox.empty():
            self.waiting.set()
        frame = self._inbox.get()
        if frame is None:
            raise EOFError("connection closed after 0/4 bytes")
        return frame

    def shutdown_read(self) -> None:
        self.events.append("shutdown_read")
        self._inbox.put(None)

    def close(self) -> None:
        self.events.append("close")


def _gateway_frames() -> list[bytes]:
    ni_reply = bytes(64)
    handle_06cf = bytearray(80)
    handle_06cf[0:2] = b"\x06\xcf"
    handle_06cf[40:48] = b"01490310"
    return [ni_reply, bytes(handle_06cf)]


def _run(
    monkeypatch: pytest.MonkeyPatch, fake: _ScriptedTransport
) -> tuple[RfcServer, threading.Thread]:
    monkeypatch.setattr(transport_mod, "connect_tcp", lambda host, port: fake)
    server = RfcServer({"program_id": "ZFTNT_SIGTEST", "gwhost": "gw", "gwserv": "sapgw00"})
    thread = threading.Thread(target=server._serve_blocking, daemon=True)
    thread.start()
    return server, thread


def test_stop_sends_listen_end_last_then_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _ScriptedTransport(_gateway_frames())
    server, thread = _run(monkeypatch, fake)
    assert fake.waiting.wait(5)

    server.stop()
    thread.join(5)

    assert not thread.is_alive()
    assert fake.sent[-1] == _payload("server_listen_end")
    assert fake.events[-3:] == ["shutdown_read", "send", "close"]


def test_stop_before_first_call_still_sends_listen_end(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _ScriptedTransport(_gateway_frames()[:1])  # no 06cf yet
    server, thread = _run(monkeypatch, fake)
    assert fake.waiting.wait(5)

    server.stop()
    thread.join(5)

    assert not thread.is_alive()
    assert fake.sent[-1] == _payload("server_listen_end")


def test_gateway_close_sends_no_listen_end(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _ScriptedTransport(_gateway_frames(), eof_after_script=True)
    _, thread = _run(monkeypatch, fake)
    thread.join(5)

    assert not thread.is_alive()
    assert _payload("server_listen_end") not in fake.sent
    assert fake.events[-1] == "close"


def test_idle_06ce_keeps_handle_and_gets_no_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    """06ce is an idle frame: no reply, and the next call uses the 06cf handle."""
    idle = _payload("server_idle_06ce")
    inbound = bytearray(80)
    inbound[0:2] = b"\x06\x03"
    fake = _ScriptedTransport([*_gateway_frames(), idle, bytes(inbound)])
    replies: list[bytes] = []
    monkeypatch.setattr(
        RfcServer,
        "_dispatch_and_reply_sync",
        lambda self, t, frame, gw_handle: replies.append(gw_handle),
    )
    server, thread = _run(monkeypatch, fake)
    assert fake.waiting.wait(5)
    sent_before_stop = len(fake.sent)

    server.stop()
    thread.join(5)

    assert replies == [b"01490310"]
    assert sent_before_stop == 3  # NI init, TPNAME, 06d1 — nothing for 06ce
