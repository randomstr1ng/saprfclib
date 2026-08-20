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

__all__ = [
    "Transport",
    "build_ni_frame",
    "parse_ni_frame",
    "connect_tcp",
    "AsyncTransport",
    "connect_tcp_async",
]


# framing.md lines 355-368 reference implementation: 4-byte big-endian uint32.
_NI_HEADER = struct.Struct(">I")
_NI_HEADER_SIZE = _NI_HEADER.size  # 4


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

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def send_message(self, payload: bytes) -> None:
        """Send one NI-framed message (4-byte BE length prefix + payload)."""
        self._sock.sendall(build_ni_frame(payload))

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
        return _recv_exactly(self._sock, length)

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


def connect_tcp(host: str, port: int, *, timeout: float | None = None) -> Transport:
    """Open a blocking TCP socket and return a Transport bound to it.

    Sets TCP_NODELAY so small RFC frames are not delayed by Nagle's algorithm.
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return Transport(sock)


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
    ) -> None:
        self._reader = reader
        self._writer = writer

    async def send_message(self, payload: bytes) -> None:
        """Send one NI-framed message (4-byte BE length prefix + payload).

        Awaits drain() after write to enforce backpressure (Pitfall 6).
        """
        self._writer.write(_NI_HEADER.pack(len(payload)) + payload)
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
        return await self._reader.readexactly(length)

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
) -> AsyncTransport:
    """Open an asyncio TCP connection and return an AsyncTransport.

    Sets TCP_NODELAY so small RFC frames are not delayed by Nagle's algorithm,
    mirroring the sync connect_tcp behaviour (transport.py:119-126).
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=timeout,
    )
    sock = writer.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return AsyncTransport(reader, writer)
