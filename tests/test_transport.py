# tests/test_transport.py
#
# Unit tests for the saprfclib NI/TCP transport seam (TRANS-08).
#
# All tests are offline (no real network): a socket.socketpair() gives a
# loopback peer for the blocking socket Transport, and tests/_mocks.MockTransport
# covers the sans-I/O byte-queue seam. The contract under test:
#   - build_ni_frame / parse_ni_frame round-trip (4-byte BE length prefix that
#     EXCLUDES the header itself).
#   - recv_message reassembles a frame split across multiple TCP reads
#     (the short-read guard, RESEARCH Pitfall 1).
#   - an oversized declared NI length is rejected (ValueError) BEFORE any payload
#     bytes are read (DoS guard, threat T-03-DOS).
#   - a truncated stream raises EOFError (threat T-03-TRUNC).

import socket
import struct
import threading

import pytest

from saprfclib.transport import Transport, build_ni_frame, connect_tcp, parse_ni_frame
from tests._mocks import MockTransport


def _make_loopback() -> "tuple[Transport, socket.socket]":
    """Return (client_transport, server_raw_socket) over a socketpair (no network)."""
    client_sock, server_sock = socket.socketpair()
    return Transport(client_sock), server_sock


# --------------------------------------------------------------------------- #
# Wire-level helpers
# --------------------------------------------------------------------------- #
def test_build_parse_ni_frame_roundtrip():
    """build_ni_frame then parse_ni_frame returns (len(p), p); prefix excludes header."""
    payload = b"\xde\xad\xbe\xef"
    frame = build_ni_frame(payload)
    # Length prefix is big-endian and counts only the payload, not the 4 header bytes.
    assert frame[:4] == struct.pack(">I", len(payload))
    length, body = parse_ni_frame(frame)
    assert length == len(payload)
    assert body == payload


def test_build_ni_frame_length_excludes_header():
    """build_ni_frame(b'abc') == b'\\x00\\x00\\x00\\x03abc' (length excludes header)."""
    assert build_ni_frame(b"abc") == b"\x00\x00\x00\x03abc"


# --------------------------------------------------------------------------- #
# Transport seam over a real (loopback) socket
# --------------------------------------------------------------------------- #
def test_send_recv_frame_roundtrip():
    """send_message frames a payload that parse_ni_frame splits back to (len, payload)."""
    transport, server = _make_loopback()
    try:
        payload = b"\xca\xfe"
        transport.send_message(payload)
        raw = server.recv(4096)
        length, body = parse_ni_frame(raw)
        assert length == len(payload)
        assert body == payload
    finally:
        transport.close()
        server.close()


def test_recv_message_loops_on_short_read():
    """recv_message reassembles a frame delivered across two separate TCP sends."""
    transport, server = _make_loopback()
    try:
        payload = b"0123456789ABCDEF"  # 16 bytes
        frame = build_ni_frame(payload)
        split = 6  # header (4) + 2 payload bytes in the first send

        def _drip() -> None:
            server.sendall(frame[:split])
            # Force recv_message to loop: deliver the remainder as a second send.
            server.sendall(frame[split:])

        sender = threading.Thread(target=_drip)
        sender.start()
        try:
            assert transport.recv_message() == payload
        finally:
            sender.join()
    finally:
        transport.close()
        server.close()


def test_oversized_frame_rejected():
    """A declared NI length above the cap raises ValueError before any payload read."""
    transport, server = _make_loopback()
    try:
        # Header alone: declare 256 MiB (> 128 MiB cap). No payload bytes follow.
        server.sendall(struct.pack(">I", 256 * 1024 * 1024))
        with pytest.raises(ValueError, match="exceeds cap"):
            transport.recv_message()
    finally:
        transport.close()
        server.close()


def test_recv_message_eof_raises():
    """Peer closes after a partial header → recv_message raises EOFError."""
    transport, server = _make_loopback()
    try:
        server.sendall(b"\x00\x00")  # 2 of 4 header bytes, then close
        server.close()
        with pytest.raises(EOFError):
            transport.recv_message()
    finally:
        transport.close()


# --------------------------------------------------------------------------- #
# connect_tcp factory (offline: connect to a local listener)
# --------------------------------------------------------------------------- #
def test_connect_tcp_returns_transport():
    """connect_tcp opens a real TCP socket to a local listener and frames a message."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    transport = None
    accepted = None
    try:
        transport = connect_tcp(host, port, timeout=5.0)
        assert isinstance(transport, Transport)
        accepted, _ = listener.accept()
        transport.send_message(b"hi")
        length, body = parse_ni_frame(accepted.recv(4096))
        assert (length, body) == (2, b"hi")
    finally:
        if transport is not None:
            transport.close()
        if accepted is not None:
            accepted.close()
        listener.close()


# --------------------------------------------------------------------------- #
# MockTransport seam double (sans-I/O — used by upper-layer plans)
# --------------------------------------------------------------------------- #
def test_mock_transport_records_sent_and_pops_responses_fifo():
    """MockTransport records sent payloads and returns scripted responses FIFO."""
    mock = MockTransport(responses=[b"r1", b"r2"])
    mock.send_message(b"s1")
    mock.send_message(b"s2")
    assert mock.sent == [b"s1", b"s2"]
    assert mock.recv_message() == b"r1"
    assert mock.recv_message() == b"r2"


def test_mock_transport_raises_eof_when_script_exhausted():
    """MockTransport raises EOFError once its response script is exhausted."""
    mock = MockTransport()
    with pytest.raises(EOFError):
        mock.recv_message()


def test_mock_transport_close_is_noop():
    """MockTransport.close() flips closed to True without error."""
    mock = MockTransport()
    assert mock.closed is False
    mock.close()
    assert mock.closed is True
