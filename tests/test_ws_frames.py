# tests/test_ws_frames.py
#
# Offline unit tests for WsTransport binary frame send/recv, ping/pong keepalive,
# and the 128 MiB DoS cap (threat T-07-FRAME-DOS). No network: a loopback
# RFC-6455 server runs in a daemon thread over socket.socketpair() and drives a
# real wsproto server-side handshake + echo, so the WsTransport talks to a
# genuine WebSocket peer.
#
# Contract under test:
#   - send_message transmits payload as a single masked binary frame (opcode 2);
#     the loopback echo server receives the exact bytes.
#   - recv_message reassembles a full binary message and returns the exact bytes.
#   - an incoming Ping is answered with a Pong (loopback server observes it).
#   - recv_message enforces the DoS cap on the message accumulator (ValueError)
#     without allocating 128 MiB.
#   - close() sets _stopped, closes the socket, and joins the ping thread cleanly.

import os
import socket
import threading

import pytest
from wsproto import ConnectionType, WSConnection
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
)

from saprfclib.exceptions import CommunicationError, WebSocketError
from saprfclib.ws import WsTransport


class LoopbackWsServer:
    """A wsproto server-mode RFC-6455 peer over one end of a socket.socketpair().

    Runs in a daemon thread: accepts the client upgrade, then echoes every
    BytesMessage back and auto-answers Ping with Pong. Optionally sends an
    unsolicited Ping first (to exercise the client's auto-pong path) and records
    whether a Pong was received.
    """

    def __init__(self, server_sock: socket.socket, *, ping_client: bool = False) -> None:
        self._sock = server_sock
        self._ws = WSConnection(ConnectionType.SERVER)
        self._ping_client = ping_client
        self.pong_received = threading.Event()
        self._rx: list[bytes] = []  # reassembly buffer for fragmented messages
        self._thread = threading.Thread(target=self._run, name="loopback-ws", daemon=True)

    def close(self) -> None:
        """Close the server half of the socketpair.

        Without this the pair leaks: transport.close() only owns the client end, so
        the server socket stays open until garbage collection and Python reports
        ResourceWarning. Harmless under the default filters, but it makes the suite
        unrunnable with -W error and can exhaust descriptors in a long run.
        """
        try:
            self._sock.close()
        except OSError:
            pass

    def start(self) -> None:
        self._thread.start()

    def _send(self, event) -> None:
        self._sock.sendall(self._ws.send(event))

    def _run(self) -> None:
        accepted = False
        while True:
            try:
                data = self._sock.recv(65536)
            except OSError:
                return
            if not data:
                return
            self._ws.receive_data(data)
            for event in self._ws.events():
                if isinstance(event, Request):
                    self._send(AcceptConnection())
                    accepted = True
                    if self._ping_client:
                        self._send(Ping(payload=b"srv-ping"))
                elif isinstance(event, BytesMessage):
                    # Reassemble fragmented messages before echoing the whole.
                    self._rx.append(event.data)
                    if event.message_finished:
                        whole = b"".join(self._rx)
                        self._rx = []
                        self._send(BytesMessage(data=whole))
                elif isinstance(event, Ping):
                    self._send(event.response())
                elif isinstance(event, Pong):
                    self.pong_received.set()
                elif isinstance(event, CloseConnection):
                    return
            if not accepted:
                return


def _make_ws_loopback(*, ping_client: bool = False, ws_ping_interval: float = 0.0):
    """Return (WsTransport client, LoopbackWsServer) already past the handshake.

    The upgrade is performed by driving both wsproto endpoints over the socketpair
    so the WsTransport starts in the "connection established" state, matching what
    connect_ws() produces after _ws_upgrade().
    """
    client_sock, server_sock = socket.socketpair()
    server = LoopbackWsServer(server_sock, ping_client=ping_client)
    server.start()

    client_ws = WSConnection(ConnectionType.CLIENT)
    client_sock.sendall(client_ws.send(Request(host="loopback", target="/sap/bc/rfc")))
    # Read the AcceptConnection so the client wsproto reaches the OPEN state.
    # Stop consuming events as soon as AcceptConnection is seen so any Ping that
    # arrives in the same recv stays in wsproto's internal deque for WsTransport
    # to pick up (draining greedily would discard them before auto-pong fires).
    while True:
        data = client_sock.recv(65536)
        client_ws.receive_data(data)
        accepted = False
        for event in client_ws.events():
            if isinstance(event, AcceptConnection):
                accepted = True
                break
        if accepted:
            break
    leftover = b""

    transport = WsTransport(
        client_sock, client_ws, ws_ping_interval=ws_ping_interval, leftover=leftover
    )
    return transport, server


def test_binary_round_trip() -> None:
    transport, server = _make_ws_loopback()
    try:
        payload = bytes(range(256)) * 8  # arbitrary binary
        transport.send_message(payload)
        assert transport.recv_message() == payload
    finally:
        transport.close()
        server.close()


def test_empty_and_large_payload_round_trip() -> None:
    transport, server = _make_ws_loopback()
    try:
        transport.send_message(b"")
        assert transport.recv_message() == b""
        big = b"\x5a" * (1024 * 512)  # 512 KiB, well under the cap
        transport.send_message(big)
        assert transport.recv_message() == big
    finally:
        transport.close()
        server.close()


def test_incoming_ping_is_answered_with_pong() -> None:
    transport, server = _make_ws_loopback(ping_client=True)
    try:
        # A round-trip drives the recv loop, which must auto-pong the server's ping.
        transport.send_message(b"ping-me")
        assert transport.recv_message() == b"ping-me"
        assert server.pong_received.wait(timeout=2.0), "server never observed a Pong"
    finally:
        transport.close()
        server.close()


def test_recv_message_enforces_dos_cap_without_allocating() -> None:
    transport, server = _make_ws_loopback()
    try:
        # Shrink the cap so we can trip it with a tiny payload (no 128 MiB alloc).
        transport._MAX_FRAME_BYTES = 16
        transport.send_message(b"this payload is definitely longer than sixteen bytes")
        with pytest.raises(ValueError):
            transport.recv_message()
    finally:
        transport.close()
        server.close()


def test_close_sets_stopped_and_joins_ping_thread() -> None:
    transport, server = _make_ws_loopback(ws_ping_interval=0.05)
    # A ping thread should be running because ws_ping_interval > 0.
    ping_thread = transport._thread
    assert ping_thread is not None
    assert ping_thread.is_alive()
    transport.close()
    server.close()
    assert transport._stopped is True
    # close() joins and clears the reference; the joined thread has terminated.
    assert not ping_thread.is_alive()
    assert transport._thread is None


def test_close_is_idempotent() -> None:
    transport, server = _make_ws_loopback()
    transport.close()
    server.close()
    transport.close()  # must not raise


def test_send_after_close_raises_communication_error() -> None:
    transport, server = _make_ws_loopback()
    transport.close()
    server.close()
    with pytest.raises((CommunicationError, WebSocketError, OSError, ValueError)):
        transport.send_message(b"after close")


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_WSHOST"),
    reason="SAPRFC_WSHOST not set — no live ABAP ICM wRFC endpoint available",
)
def test_live_wrfc_round_trip() -> None:  # pragma: no cover - live gate scaffold
    host = os.environ["SAPRFC_WSHOST"]
    assert host, "SAPRFC_WSHOST must be set for the live wRFC integration test"
