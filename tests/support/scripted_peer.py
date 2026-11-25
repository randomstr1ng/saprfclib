# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""A scripted SAP peer on a real loopback socket, with fault injection (#87).

The mocks in tests/_mocks.py hand the client whole payloads, so the NI framing and
the session stack above it never see the network misbehave. This peer is a TCP
server on 127.0.0.1 that speaks NI framing (a 4-byte big-endian length, then the
payload), records every frame the client sends, and answers from a script. Each
reply can be delivered damaged: split into pieces, merged with the next one,
delayed, duplicated, truncated, with its length prefix rewritten; and the peer can
reset, half-close or close the connection at any point.

Replies come from golden fixtures, so what the client parses are real captured
bytes; only the delivery is staged.

A script is a list of steps per connection. The peer serves the scripts in order,
one per accepted connection, which is how a reconnect is tested. Every script is
bounded (``MAX_STEPS`` steps, ``MAX_DELAY`` seconds per delay, ``MAX_BYTES`` bytes in
all) and every socket operation has a timeout, so a broken test fails instead of
hanging. Errors inside the peer are collected and raised by ``close()``.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field

MAX_STEPS = 256
MAX_DELAY = 5.0
MAX_BYTES = 8 * 1024 * 1024
IO_TIMEOUT = 10.0


@dataclass(frozen=True)
class Expect:
    """Read one NI frame from the client and record its payload."""


@dataclass(frozen=True)
class Reply:
    """Send ``payload`` as one NI frame, optionally damaged on the way.

    Attributes:
        chunks: send the frame (length prefix included) in pieces of these sizes,
            ``pause`` seconds apart; the remainder goes in a last piece.
        delay: wait this long before sending.
        truncate: send only the first N bytes of the frame, then close.
        length_delta: add this to the declared NI length (the payload is unchanged).
        length_override: declare this NI length instead (the payload is unchanged).
        duplicate: send the frame twice.
        coalesce: hold the frame back and send it in one write with the next Reply.
    """

    payload: bytes
    chunks: tuple[int, ...] = ()
    pause: float = 0.01
    delay: float = 0.0
    truncate: int | None = None
    length_delta: int = 0
    length_override: int | None = None
    duplicate: bool = False
    coalesce: bool = False


@dataclass(frozen=True)
class Delay:
    seconds: float


@dataclass(frozen=True)
class HalfClose:
    """Shut down the peer's write side: the client reads EOF, the peer can still read."""


@dataclass(frozen=True)
class Close:
    """Close the connection normally (FIN)."""


@dataclass(frozen=True)
class Reset:
    """Abort the connection (RST): SO_LINGER with a zero timeout, then close."""


Step = Expect | Reply | Delay | HalfClose | Close | Reset


def _validate(script: list[Step]) -> None:
    if len(script) > MAX_STEPS:
        raise ValueError(f"script has {len(script)} steps, the limit is {MAX_STEPS}")
    total = 0
    for step in script:
        if isinstance(step, Delay | Reply):
            seconds = step.seconds if isinstance(step, Delay) else step.delay
            if not 0 <= seconds <= MAX_DELAY:
                raise ValueError(f"delay {seconds} is outside 0..{MAX_DELAY} s")
        if isinstance(step, Reply):
            total += (len(step.payload) + 4) * (2 if step.duplicate else 1)
    if total > MAX_BYTES:
        raise ValueError(f"script sends {total} bytes, the limit is {MAX_BYTES}")


@dataclass
class PeerConnection:
    """What happened on one accepted connection."""

    received: list[bytes] = field(default_factory=list)
    closed_by_client: bool = False


class ScriptedPeer:
    """Serve ``scripts`` in order, one per accepted connection, on 127.0.0.1.

    Use as a context manager. ``port`` is where the client connects; after the
    ``with`` block, ``connections`` holds what each connection received.
    """

    def __init__(self, *scripts: list[Step]) -> None:
        for script in scripts:
            _validate(script)
        self._scripts = list(scripts)
        self.connections: list[PeerConnection] = []
        self._errors: list[BaseException] = []
        self._server = socket.create_server(("127.0.0.1", 0))
        self._server.settimeout(IO_TIMEOUT)
        self.port: int = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name="scripted-peer", daemon=True)

    def __enter__(self) -> ScriptedPeer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._thread.join(IO_TIMEOUT * 2)
        self._server.close()
        if self._thread.is_alive():
            raise AssertionError("scripted peer did not finish its scripts in time")
        if self._errors:
            raise AssertionError(f"scripted peer failed: {self._errors[0]!r}") from self._errors[0]

    # -- server side ------------------------------------------------------- #

    def _serve(self) -> None:
        try:
            for script in self._scripts:
                sock, _ = self._server.accept()
                sock.settimeout(IO_TIMEOUT)
                record = PeerConnection()
                self.connections.append(record)
                with sock:
                    self._run(sock, script, record)
        except BaseException as exc:  # noqa: BLE001 - reported by close()
            self._errors.append(exc)
        finally:
            # No script left: refuse further connections at once rather than leave
            # them waiting in the listen backlog until a client timeout.
            self._server.close()

    def _run(self, sock: socket.socket, script: list[Step], record: PeerConnection) -> None:
        held = b""
        for step in script:
            if isinstance(step, Expect):
                frame = _read_frame(sock)
                if frame is None:
                    record.closed_by_client = True
                    return
                record.received.append(frame)
            elif isinstance(step, Reply):
                held = self._reply(sock, step, held)
                if step.truncate is not None:
                    return
            elif isinstance(step, Delay):
                time.sleep(step.seconds)
            elif isinstance(step, HalfClose):
                sock.shutdown(socket.SHUT_WR)
            elif isinstance(step, Close):
                return
            elif isinstance(step, Reset):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                return
        if held:
            sock.sendall(held)
        # Script done: wait for the client to close, so its last frame is recorded
        # rather than lost to an early FIN.
        while _read_frame(sock) is not None:
            pass
        record.closed_by_client = True

    @staticmethod
    def _reply(sock: socket.socket, step: Reply, held: bytes) -> bytes:
        if step.delay:
            time.sleep(step.delay)
        length = step.length_override if step.length_override is not None else len(step.payload)
        frame = struct.pack(">I", length + step.length_delta) + step.payload
        if step.duplicate:
            frame += frame
        if step.truncate is not None:
            frame = frame[: step.truncate]
        data = held + frame
        if step.coalesce:
            return data
        if step.chunks:
            pos = 0
            for size in step.chunks:
                sock.sendall(data[pos : pos + size])
                pos += size
                time.sleep(step.pause)
            if pos < len(data):
                sock.sendall(data[pos:])
        else:
            sock.sendall(data)
        return b""


def _read_frame(sock: socket.socket) -> bytes | None:
    """One NI frame's payload, or None if the client closed the connection."""
    header = _read_exactly(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length > MAX_BYTES:
        raise ValueError(f"client declared a {length}-byte frame")
    payload = _read_exactly(sock, length)
    if payload is None:
        raise EOFError(f"client closed inside a {length}-byte frame")
    return payload


def _read_exactly(sock: socket.socket, n: int) -> bytes | None:
    """``n`` bytes, or None if the client closed before sending any of them."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except ConnectionResetError:
            chunk = b""
        if not chunk:
            if not buf:
                return None
            raise EOFError(f"client closed after {len(buf)} of {n} bytes")
        buf += chunk
    return bytes(buf)
