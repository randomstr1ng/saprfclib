# SPDX-License-Identifier: MPL-2.0
"""RFC trace files in the SAP NW RFC SDK's format (#21).

The SDK writes ``.trc`` files that SAP support and existing tooling can read, and
that a developer can diff against this library's own output. That diff is not a
hypothetical use: comparing an SDK trace against saprfclib's traffic is what
identified every defect behind issue #14, and doing it required parsing the SDK's
format by hand because there was nothing to compare against.

The format, as observed in SDK 7.50 PL18 output::

    **** Trace file opened at 2026-09-02 09:00:28.987174 UTC+02:00 (GMT), Encoding UTF-8
    NW RFC Library: ...
    <header block, one "key : value" per line>

    2026-09-02 09:00:28.987160 [131494078863360] >> API RfcOpenConnection
    ...
    >> HEXDUMP
    2026-09-02 09:09:12.143259 [138677199988736] Writing 8 bytes on Socket 1, handle 101540996251264
    000000 | 82FE00EE 26D4004C 00000000 00000000 |....&..L........|
    << HEXDUMP

Credentials are redacted, which the SDK's own traces do not do. A level-4 SDK
trace dumps the LOGON frame verbatim, and that frame carries tag 0x0117: the
password scrambled with a seed that travels beside it. That is obfuscation, not
encryption, so an SDK trace is a file from which the password can be recovered --
which is why the capture scripts written during #14 scrub them before copying.
Producing files with the same property would be handing users a footgun with an
official-looking name, so 0x0117 values are zeroed before anything is written.
"""

from __future__ import annotations

import datetime
import os
import struct
import threading
from types import TracebackType
from typing import IO

__all__ = ["RfcTrace", "TRACE_OFF", "TRACE_BRIEF", "TRACE_VERBOSE", "TRACE_FULL"]

TRACE_OFF = 0
TRACE_BRIEF = 1  # API entry and exit
TRACE_VERBOSE = 2  # + connection lifecycle
TRACE_FULL = 3  # + hex dumps of every frame

# Password material. Redacted wherever it appears, in either wire dialect.
_TAG_PASSWORD = 0x0117
_TERMINATOR = 0xFFFF
_GW_HEADER_LEN = 80


def redact(payload: bytes) -> bytes:
    """Return ``payload`` with any password TLV zeroed, same length.

    Walks the record stream and blanks the value of tag 0x0117. Length is
    preserved so every offset in the dump still lines up with the real frame --
    a redaction that shifted the bytes would make the trace useless for the
    comparison it exists to support.

    A payload that is not a record stream is returned unchanged: there is nothing
    to find, and guessing at offsets in an unrecognised frame could blank real
    data while leaving a credential in place.
    """
    body_at = _GW_HEADER_LEN if payload[:1] == b"\x06" and len(payload) > _GW_HEADER_LEN else 0
    out = bytearray(payload)
    pos, n = body_at, len(payload)
    while pos + 4 <= n:
        tag, length = struct.unpack_from(">HH", out, pos)
        pos += 4
        if tag == _TERMINATOR:
            break
        if length == 0xFFFF:
            if pos + 4 > n:
                break
            length = struct.unpack_from(">I", out, pos)[0]
            pos += 4
        if pos + length > n:
            break
        if tag == _TAG_PASSWORD:
            out[pos : pos + length] = b"\x00" * length
        pos += length
        if pos + 2 <= n and struct.unpack_from(">H", out, pos)[0] == tag:
            pos += 2
    return bytes(out)


def _hexdump(data: bytes) -> list[str]:
    """The SDK's dump layout: ``OFFSET | HEX HEX HEX HEX |ASCII|``."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16].ljust(16, b"\x00")
        groups = " ".join(chunk[i : i + 4].hex().upper() for i in range(0, 16, 4))
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[off : off + 16])
        lines.append(f"{off:06X} | {groups} |{text:<16}|")
    return lines


class RfcTrace:
    """A trace file in the SDK's format. Not thread-shared: one per connection.

    Writes are serialised with a lock because a connection's I/O may be driven
    from a background loop thread while the owning thread logs API entry, and
    interleaved half-lines would make the file unparseable by the tooling this
    exists to feed.
    """

    def __init__(self, path: str, *, level: int = TRACE_FULL) -> None:
        self.level = level
        self.path = path
        self._lock = threading.Lock()
        self._fh: IO[str] | None = open(path, "w", encoding="utf-8")  # noqa: SIM115
        self._write_header()

    # -- lifecycle ---------------------------------------------------------- #

    def __enter__(self) -> RfcTrace:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    # -- writing ------------------------------------------------------------ #

    def _now(self) -> str:
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    def _emit(self, text: str) -> None:
        with self._lock:
            if self._fh is None:
                return
            self._fh.write(text + "\n")
            self._fh.flush()

    def _write_header(self) -> None:
        from saprfclib import __version__

        opened = datetime.datetime.now().astimezone()
        self._emit(
            f"**** Trace file opened at {opened.strftime('%Y-%m-%d %H:%M:%S.%f')} "
            f"{opened.strftime('%z')}, Encoding UTF-8"
        )
        for key, value in (
            ("saprfclib", __version__),
            ("Program", os.path.basename(__import__("sys").argv[0]) or "python"),
            ("Process", str(os.getpid())),
            ("Trace level", str(self.level)),
            ("Credentials", "REDACTED (tag 0x0117 zeroed in every dump)"),
        ):
            self._emit(f"{key:<26}: {value}")
        self._emit("")

    def log(self, message: str, *, level: int = TRACE_BRIEF) -> None:
        """One timestamped line, if ``level`` is within the configured level."""
        if self.level < level:
            return
        self._emit(f"{self._now()} [{threading.get_ident()}] {message}")

    def frame(self, direction: str, payload: bytes, *, socket_id: int = 1) -> None:
        """Hex-dump one frame, credentials removed.

        ``direction`` is "Writing" or "Read", matching the SDK's wording so the
        two files diff cleanly.
        """
        if self.level < TRACE_FULL:
            return
        safe = redact(payload)
        self._emit(">> HEXDUMP")
        self._emit(
            f"{self._now()} [{threading.get_ident()}] "
            f"{direction} {len(payload)} bytes on Socket {socket_id}"
        )
        for line in _hexdump(safe):
            self._emit(line)
        self._emit("<< HEXDUMP")
        self._emit("")
