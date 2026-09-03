# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — NI/TCP transport
#
# Blocking socket transport: the NI-frame send/recv seam (TRANS-08). Owns the
# 4-byte big-endian length prefix at the NI layer; everything above it (the
# APPC/GW header, the RFC TLV stream) is the Session/RFC layer's concern.
#
#     send_message(payload: bytes) -> None  -- wraps payload in an NI frame, writes it
#     recv_message() -> bytes               -- reads the 4-byte length, then exactly
#                                              that many payload bytes
#
# The send_message / recv_message seam is the substitution point for the future
# WebSocket (Phase 7) and SNC transports — the Session never touches sockets.
#
# Wire-level helpers (build_ni_frame / parse_ni_frame) are copied from the
# docs/protocol/framing.md reference implementation (lines 355-368): a 4-byte
# big-endian uint32 length prefix that EXCLUDES the header itself.
#
# Two guards protect every later phase (threat register, plan 03-01):
#   - T-03-DOS: recv_message rejects a declared length above _MAX_FRAME_BYTES
#     (128 MiB) with ValueError BEFORE reading/allocating the payload (ASVS V5).
#   - T-03-TRUNC: _recv_exactly treats a zero-length recv as EOF and never
#     returns a partial frame as if it were complete (TCP short-read guard,
#     RESEARCH Pitfall 1).
from __future__ import annotations

import asyncio
import socket
import struct
from typing import cast

from saprfclib.exceptions import SapRfcError
from saprfclib.trace import RfcTrace

__all__ = [
    "Transport",
    "build_ni_frame",
    "parse_ni_frame",
    "connect_tcp",
    "AsyncTransport",
    "connect_tcp_async",
    "raise_for_ni_error",
    "is_ni_pong",
    "enable_keepalive",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
]

# Connecting and waiting for an answer are different waits and need different
# limits. A TCP connect that has not completed in 10s is not going to; an RFC
# call that has not answered in 10s may simply be a large BAPI still running.
# Passing one number for both — which socket.create_connection does, since its
# timeout becomes the socket's per-operation timeout — forces a choice between
# hanging forever on a wedged work process and aborting legitimate long calls.
DEFAULT_CONNECT_TIMEOUT = 10.0

# None means "wait as long as the server takes". That is the correct default for
# a protocol with no server-side call-duration bound: capping it would abort
# valid work. It is dangerous only when the peer goes away silently without
# closing the socket, which is what keepalive below is for.
DEFAULT_READ_TIMEOUT: float | None = None

# TCP keepalive probing. A stateful firewall or NAT between client and SAP will
# silently drop an idle mapping, and neither end is told. Without keepalive the
# next recv() blocks until the OS default gives up (two hours on Linux), which
# in practice means a hung application. These values start probing after 60s of
# idle and give up after 5 failed probes at 10s intervals, so a dead path is
# detected in ~110s rather than ~2h.
_KEEPALIVE_IDLE = 60
_KEEPALIVE_INTERVAL = 10
_KEEPALIVE_COUNT = 5


def enable_keepalive(sock: socket.socket) -> None:
    """Turn on TCP keepalive with probe timings suited to RFC connections.

    The per-timing options are platform-specific and simply absent on some
    systems; each is applied only if this platform defines it, so enabling
    keepalive never fails on a platform that spells the knobs differently. The
    base SO_KEEPALIVE flag is portable and is what actually matters — the
    timings only shorten the detection window from the OS default.
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for name, value in (
        ("TCP_KEEPIDLE", _KEEPALIVE_IDLE),
        ("TCP_KEEPINTVL", _KEEPALIVE_INTERVAL),
        ("TCP_KEEPCNT", _KEEPALIVE_COUNT),
    ):
        option = getattr(socket, name, None)
        if option is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
            except OSError:  # pragma: no cover - platform-dependent
                # The flag is set; only the timing refinement was refused.
                pass


# framing.md lines 355-368 reference implementation: 4-byte big-endian uint32.
_NI_HEADER = struct.Struct(">I")
_NI_HEADER_SIZE = _NI_HEADER.size  # 4


# NI control messages are 8-byte ASCII payloads the NI layer handles itself,
# before anything reaches the RFC layer (docs/protocol/framing.md). NI_RTERR is
# how a SAProuter reports that it will not carry the route — wrong password,
# route denied by the router's permission table, or the target unreachable.
#
# Nothing here claims to know what follows the marker, and nothing needs to: the
# marker alone identifies the frame as a router refusal. Without this check that
# frame reaches the session as if it were the NI version response and is
# misparsed, so a rejected route surfaces as a confusing protocol error several
# steps later instead of as "the router said no".
_NI_RTERR = b"NI_RTERR"
_NI_PONG = b"NI_PONG"

_NI_ERROR_FALLBACK = (
    "the SAProuter refused the route. Common causes: the route is not permitted "
    "by the router's permission table, a hop password is wrong or missing, or the "
    "target host/port is unreachable from the router"
)


def _ni_error_text(payload: bytes) -> str:
    """Pull the router's own message out of an NI_RTERR frame.

    Confirmed by live capture (tests/golden/router/ni_rterr_route_denied.bin): the
    frame carries a NUL-separated ``*ERR*`` record — the same shape the gateway
    uses — whose second field is the human-readable reason, for example
    ``saprouter: route permission denied (203.0.113.42 to 10.99.99.99, 3300)``.

    That text names the source address, the target and the port, which is exactly
    what someone debugging a denied route needs. Falls back to a generic
    explanation when the record is absent or unreadable, since the marker alone
    already establishes that the route was refused.
    """
    start = payload.find(b"*ERR*")
    if start < 0:
        return _NI_ERROR_FALLBACK
    fields = [f for f in payload[start:].split(b"\x00") if f.strip()]
    # fields[0] is the "*ERR*" sentinel, fields[1] a record number, fields[2] the
    # message. Anything shorter means a shape this has not seen.
    if len(fields) < 3:
        return _NI_ERROR_FALLBACK
    message = fields[2].decode("latin-1", "replace").strip()
    return message or _NI_ERROR_FALLBACK


def raise_for_ni_error(payload: bytes) -> None:
    """Raise if ``payload`` is an NI-layer error control message.

    Called for every inbound frame, so a router refusal is reported where it
    happens rather than as a malformed RFC frame several steps later.
    """
    if payload.startswith(_NI_RTERR):
        raise SapRfcError(f"SAProuter refused the route: {_ni_error_text(payload)}")


def is_ni_pong(payload: bytes) -> bool:
    """True if ``payload`` is the NI acknowledgement a SAProuter sends.

    Confirmed live: a router that accepts an NI_ROUTE answers with the 8-byte
    ``NI_PONG\0`` control message before it begins forwarding, and one that
    refuses answers with NI_RTERR instead.
    """
    return payload.startswith(_NI_PONG)


def build_ni_frame(payload: bytes) -> bytes:
    """Prepend the 4-byte BE NI length header (length EXCLUDES the header itself)."""
    return _NI_HEADER.pack(len(payload)) + payload


def parse_ni_frame(buf: bytes) -> tuple[int, bytes]:
    """Split a complete NI frame into (payload_length, payload).

    Caller must guarantee ``buf`` holds at least the 4-byte header plus the
    declared payload; this is the in-memory counterpart to Transport.recv_message.
    """
    (length,) = _NI_HEADER.unpack_from(buf)
    return length, buf[_NI_HEADER_SIZE : _NI_HEADER_SIZE + length]


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes from ``sock``, looping over TCP short reads.

    TCP is a byte stream: a single recv() may return fewer bytes than requested.
    This is the short-read guard (RESEARCH Pitfall 1 / threat T-03-TRUNC). A
    zero-length recv means the peer closed the stream — raise EOFError rather
    than return a truncated frame as if it were complete.
    """
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        chunk = sock.recv_into(view[received:], n - received)
        if chunk == 0:
            raise EOFError(f"connection closed after {received}/{n} bytes")
        received += chunk
    return bytes(buf)


class Transport:
    """Blocking socket transport implementing the send_message/recv_message seam."""

    # 128 MiB DoS cap (ASVS V5 / threat T-03-DOS): reject any declared NI length
    # above this before allocating or reading the payload.
    _MAX_FRAME_BYTES = 128 * 1024 * 1024

    def __init__(self, sock: socket.socket, *, trace: RfcTrace | None = None) -> None:
        self._sock = sock
        # Cumulative wire bytes, including the 4-byte NI length prefix, so the
        # figure matches what a packet capture would show rather than the
        # payload the RFC layer sees.
        self.bytes_sent = 0
        self.bytes_received = 0
        # Optional trace writer. Attached at the transport rather than higher up
        # so what lands in the file is what crossed the socket, not what some
        # layer intended to send.
        self.trace = trace

    def send_message(self, payload: bytes) -> None:
        """Send one NI-framed message (4-byte BE length prefix + payload)."""
        frame = build_ni_frame(payload)
        self._sock.sendall(frame)
        self.bytes_sent += len(frame)
        if self.trace is not None:
            self.trace.frame("Writing", payload)

    def recv_message(self) -> bytes:
        """Receive one NI-framed message; loop until complete (short-read guard).

        Reads the 4-byte length header first and rejects an oversized declared
        length (threat T-03-DOS) BEFORE reading any payload bytes.
        """
        header = _recv_exactly(self._sock, _NI_HEADER_SIZE)
        (length,) = _NI_HEADER.unpack_from(header)
        if length > self._MAX_FRAME_BYTES:
            raise ValueError(
                f"NI frame length {length} exceeds cap {self._MAX_FRAME_BYTES} (DoS guard)"
            )
        payload = _recv_exactly(self._sock, length)
        self.bytes_received += _NI_HEADER_SIZE + len(payload)
        if self.trace is not None:
            self.trace.frame("Read", payload)
        raise_for_ni_error(payload)
        return payload

    @property
    def local_address(self) -> tuple[str, int]:
        """Return the local (host, port) of the underlying socket."""
        return cast(tuple[str, int], self._sock.getsockname())

    @property
    def remote_address(self) -> tuple[str, int]:
        """Return the remote (host, port) of the underlying socket."""
        return cast(tuple[str, int], self._sock.getpeername())

    def close(self) -> None:
        """Shut down and close the socket; ignore an already-broken connection."""
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()


def connect_tcp(
    host: str,
    port: int,
    *,
    timeout: float | None = None,
    connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float | None = DEFAULT_READ_TIMEOUT,
    trace: RfcTrace | None = None,
) -> Transport:
    """Open a blocking TCP socket and return a Transport bound to it.

    Sets TCP_NODELAY so small RFC frames are not delayed by Nagle's algorithm,
    and enables TCP keepalive so a silently dropped path is detected rather than
    blocking a later read indefinitely.

    Args:
        connect_timeout: how long to wait for the TCP handshake. Defaults to
            :data:`DEFAULT_CONNECT_TIMEOUT`; ``None`` waits indefinitely.
        read_timeout: how long a single read may block once connected. Defaults
            to :data:`DEFAULT_READ_TIMEOUT` (``None`` — wait for the server),
            because RFC has no server-side bound on how long a call may take.
        timeout: deprecated single value applied to both. Kept so existing
            callers keep working; prefer the two explicit arguments, since one
            number cannot express "connect quickly, then wait as long as the
            call needs".
    """
    if timeout is not None:
        connect_timeout = timeout
        read_timeout = timeout
    sock = socket.create_connection((host, port), timeout=connect_timeout)
    # create_connection leaves its connect timeout on the socket, where it would
    # then apply to every later recv. Set the read timeout explicitly so the two
    # are never conflated by accident.
    sock.settimeout(read_timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    enable_keepalive(sock)
    return Transport(sock, trace=trace)


class AsyncTransport:
    """Asyncio-socket transport implementing the async send_message/recv_message seam.

    Wraps a (StreamReader, StreamWriter) pair from asyncio.open_connection.
    Preserves the 128 MiB NI-frame DoS cap (T-09-03-DOS) in recv_message by
    checking the declared length BEFORE calling readexactly on the payload.

    Pitfall 6: drain() is awaited after every write to enforce backpressure.
    Pitfall 6: wait_closed() is awaited in close() to avoid socket/TLS leaks.
    Pitfall 7: only (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError)
    are wrapped in the I/O methods; CancelledError is never caught.
    """

    # 128 MiB DoS cap (ASVS V5 / T-09-03-DOS): reject any declared NI length
    # above this BEFORE allocating or reading the payload (carry-over from sync Transport).
    _MAX_FRAME_BYTES = 128 * 1024 * 1024

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        trace: RfcTrace | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.bytes_sent = 0
        self.bytes_received = 0
        self.trace = trace

    async def send_message(self, payload: bytes) -> None:
        """Send one NI-framed message (4-byte BE length prefix + payload).

        Awaits drain() after write to enforce backpressure (Pitfall 6).
        """
        frame = _NI_HEADER.pack(len(payload)) + payload
        self._writer.write(frame)
        self.bytes_sent += len(frame)
        if self.trace is not None:
            self.trace.frame("Writing", payload)
        await self._writer.drain()

    async def recv_message(self) -> bytes:
        """Receive one NI-framed message; enforce 128 MiB DoS cap before allocation.

        Reads the 4-byte header with readexactly (short-read guard via stdlib).
        Raises ValueError if the declared length exceeds _MAX_FRAME_BYTES BEFORE
        reading/allocating any payload bytes (T-09-03-DOS carry-over).
        asyncio.IncompleteReadError (subclass of EOFError) is raised by readexactly
        on a clean peer close — mirrors the sync _recv_exactly EOFError guard.
        """
        header = await self._reader.readexactly(_NI_HEADER_SIZE)
        (length,) = _NI_HEADER.unpack_from(header)
        if length > self._MAX_FRAME_BYTES:
            raise ValueError(
                f"NI frame length {length} exceeds cap {self._MAX_FRAME_BYTES} (DoS guard)"
            )
        payload = await self._reader.readexactly(length)
        self.bytes_received += _NI_HEADER_SIZE + len(payload)
        if self.trace is not None:
            self.trace.frame("Read", payload)
        raise_for_ni_error(payload)
        return payload

    @property
    def local_address(self) -> tuple[str, int]:
        """Return the local (host, port) of the underlying socket."""
        sock = self._writer.get_extra_info("socket")
        if sock is not None:
            return cast(tuple[str, int], sock.getsockname())
        return ("127.0.0.1", 0)

    @property
    def remote_address(self) -> tuple[str, int]:
        """Return the remote (host, port) of the underlying socket."""
        return cast(tuple[str, int], self._writer.get_extra_info("peername") or ("127.0.0.1", 0))

    async def close(self) -> None:
        """Close the async transport; await wait_closed() to avoid resource leaks (Pitfall 6)."""
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except OSError:
            pass


async def connect_tcp_async(
    host: str,
    port: int,
    *,
    timeout: float | None = None,
    connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
    trace: RfcTrace | None = None,
) -> AsyncTransport:
    """Open an asyncio TCP connection and return an AsyncTransport.

    Sets TCP_NODELAY and enables TCP keepalive, mirroring :func:`connect_tcp`.

    There is no ``read_timeout`` here on purpose: an asyncio caller bounds a read
    with ``asyncio.wait_for`` around the await, which cancels cleanly. Setting a
    socket-level timeout underneath the event loop would not do that.

    Args:
        connect_timeout: how long to wait for the connection. Defaults to
            :data:`DEFAULT_CONNECT_TIMEOUT`; ``None`` waits indefinitely.
        timeout: deprecated alias for ``connect_timeout``.
    """
    if timeout is not None:
        connect_timeout = timeout
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=connect_timeout,
    )
    sock = writer.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        enable_keepalive(sock)
    return AsyncTransport(reader, writer, trace=trace)
