# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — SAProuter route strings + message-server group logon
#
# Two alternate-transport helpers for the Connection facade:
#
#   parse_route_string(route)              -- parse "/H/host/S/port/H/router" into RouteHops
#   build_ni_route(hops)                   -- build the NI_ROUTE control-message prefix
#   parse_sapms_server_list(payload)       -- parse SAPMS MESSAGE server-list response
#   MessageServerClient.resolve            -- legacy mock-testable resolve (Phase 3)
#   MessageServerClient.resolve_full       -- full SAPMS exchange (Phase 4, TRANS-03)
#
# Requirements: TRANS-02 (SAProuter hop routing), TRANS-03 (message-server group
# logon). Threat register: T-03-ROUTE / T-03-REDIR (validate redirect host/port
# bounds before connecting), T-03-CRED2 (never log route-string passwords),
# T-04-MSDOS (bounds-check SAPMS server count/length), T-04-MSERR (ValueError
# on SAPMS error response), T-04-REDIR (validate resolved ashost/sysnr).
#
# DON'T-HAND-ROLL split:
#   - parse_route_string is PURE STRING PARSING and is fully verified offline.
#   - build_ni_route wire format CONFIRMED from live capture 2026-06-27 (TRANS-02).
#   - parse_sapms_server_list CONFIRMED from live capture 2026-06-27 (TRANS-03).
#     Per-server entry field semantics annotated [ASSUMED] where purpose is unclear.
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from urllib.parse import quote
from urllib.request import urlopen

from saprfclib.exceptions import SapRfcError

__all__ = [
    "RouteHop",
    "build_sapms_frame",
    "parse_sapms_reply",
    "decode_ms_errorno",
    "describe_ms_errorno",
    "parse_route_string",
    "build_ni_route",
    "parse_sapms_server_list",
    "MessageServerClient",
    "MessageServerHttpError",
    "parse_ms_http_logon",
    "parse_ms_http_lglist",
    "resolve_rfc_server_http",
]


# SAProuter route-string field markers (public, well-documented syntax):
#   /H/<host>   host hop
#   /S/<service>  service/port for the preceding host
#   /P/<password> optional route password for the preceding hop
_HOST_MARKER = "H"
_SERVICE_MARKER = "S"
_PASSWORD_MARKER = "P"

# NI_ROUTE control marker.
#
# The NI_ROUTE payload built below is CONFIRMED — live capture 2026-06-27, golden
# fixture tests/golden/router/ni_route_payload.bin, byte-exact. (An older comment
# here labelled it [ASSUMED]; that predates the capture and contradicted
# build_ni_route's own docstring.)
_NI_ROUTE_MARKER = b"NI_ROUTE"


@dataclass
class RouteHop:
    """One hop in a SAProuter route chain (TRANS-02).

    ``host`` and ``service`` come from the /H and /S route-string segments;
    ``password`` (/P) and ``talk_mode`` default when absent. ``password`` is
    never logged (threat T-03-CRED2).
    """

    host: str
    service: str = ""
    password: str = ""
    talk_mode: int = 0


def parse_route_string(route: str) -> list[RouteHop]:
    """Parse a SAProuter route string into an ordered list of RouteHop.

    Accepts the `/H/host/S/service/H/host2/...` syntax. Each `/H/` starts a new
    hop; a following `/S/` sets that hop's service and `/P/` its password. Raises
    ValueError on empty or malformed input (this is pure string parsing — fully
    verifiable offline, no [ASSUMED] bytes here).
    """
    if not route or not route.startswith("/"):
        raise ValueError(
            "malformed route string: must be a non-empty '/H/host/S/service/...' chain"
        )

    # Split on '/' and drop the leading empty token from the initial '/'.
    tokens = list(route.split("/"))
    if tokens and tokens[0] == "":
        tokens = tokens[1:]
    if not tokens:
        raise ValueError("malformed route string: no hops found")

    hops: list[RouteHop] = []
    i = 0
    n = len(tokens)
    while i < n:
        marker = tokens[i]
        if marker == _HOST_MARKER:
            if i + 1 >= n:
                raise ValueError("malformed route string: /H/ without a host value")
            hops.append(RouteHop(host=tokens[i + 1]))
            i += 2
        elif marker == _SERVICE_MARKER:
            if not hops:
                raise ValueError("malformed route string: /S/ before any /H/ host")
            if i + 1 >= n:
                raise ValueError("malformed route string: /S/ without a service value")
            hops[-1].service = tokens[i + 1]
            i += 2
        elif marker == _PASSWORD_MARKER:
            if not hops:
                raise ValueError("malformed route string: /P/ before any /H/ host")
            if i + 1 >= n:
                raise ValueError("malformed route string: /P/ without a password value")
            hops[-1].password = tokens[i + 1]
            i += 2
        else:
            raise ValueError(
                f"malformed route string: unknown marker {marker!r} (expected one of H/S/P)"
            )

    if not hops:
        raise ValueError("malformed route string: no /H/ host hops found")
    return hops


def build_ni_route(hops: list[RouteHop], dest_host: str, dest_service: str) -> bytes:
    """Build the NI_ROUTE control-message payload for a SAProuter hop chain.

    Wire format CONFIRMED from live capture 2026-06-27 (TRANS-02):

        "NI_ROUTE\\0"       9 bytes (null-terminated magic)
        talk_mode           1 byte  (0x02)
        0x28                1 byte  (fixed)
        route_version       1 byte  (0x02)
        hop_count           4 bytes BE
        total_data_length   4 bytes BE (sum of entry data + final dest data, NOT entry_length fields)
        For each intermediate hop:
            entry_length    4 bytes BE = len(host_null) + 6
            host            null-terminated ASCII
            service         6 bytes, null-padded
        Final destination (no length prefix):
            host            null-terminated ASCII
            service         6 bytes, null-padded

    Returns raw payload (no NI 4-byte length header) — caller uses
    Transport.send_message() which adds NI framing.

    ``hops`` are intermediate SAProuter nodes from parse_route_string().
    ``dest_host`` / ``dest_service`` are the final app-server host and gateway
    port string (e.g. "192.168.88.7", "3300").
    """
    if not hops:
        raise ValueError("build_ni_route: at least one hop is required")

    # A /P/ password is parsed into RouteHop.password but there is no captured
    # evidence of where it goes in the frame, so it cannot be sent. Connecting
    # without it is not a graceful degradation: the router refuses the route and
    # the caller is left with a rejection they have no way to attribute to the
    # password they carefully supplied. Fail here instead, naming the gap.
    protected = [h.host for h in hops if h.password]
    if protected:
        raise NotImplementedError(
            f"SAProuter hop password (/P/) is not implemented, and hop(s) "
            f"{', '.join(protected)} specify one. The route-string parser reads the "
            f"password but its position in the NI_ROUTE frame has never been "
            f"captured, so sending the route without it would simply be refused by "
            f"the router with no indication why. See docs/protocol/message_server.md "
            f"for what a capture needs to contain."
        )

    def _null_term(s: str) -> bytes:
        return s.encode("ascii") + b"\x00"

    def _pad_service(s: str) -> bytes:
        b = s.encode("ascii")[:6]
        return b.ljust(6, b"\x00")

    hop_entries: list[tuple[bytes, bytes]] = [
        (_null_term(h.host), _pad_service(h.service)) for h in hops
    ]
    dest_data = _null_term(dest_host) + _pad_service(dest_service)

    # total_data_length excludes the 4-byte entry_length fields.
    total_data = sum(len(hb) + len(sb) for hb, sb in hop_entries) + len(dest_data)

    out = bytearray()
    out += b"NI_ROUTE\x00"  # 9 bytes, null-terminated
    out += bytes([0x02])  # talk_mode
    out += bytes([0x28])  # fixed byte confirmed from live capture
    out += bytes([0x02])  # route_version
    out += struct.pack(">I", len(hops))  # hop_count
    out += struct.pack(">I", total_data)  # total_data_length
    for hb, sb in hop_entries:
        entry_data = hb + sb
        out += struct.pack(">I", len(entry_data))  # entry_length
        out += entry_data
    out += dest_data
    return bytes(out)


# ---------------------------------------------------------------------------
# SAPMS MESSAGE server-list frame constants (wire-captured 2026-06-27, TRANS-03)
# ---------------------------------------------------------------------------

# Fixed magic string at offset 4..14 (11 bytes, wire-captured).
_SAPMS_MAGIC = b"**MESSAGE**"

# Header size in bytes before the per-server entries begin (wire-captured).
# Layout:
#   [0:4]   NI length prefix (4 bytes BE)
#   [4:15]  magic "**MESSAGE**" (11 bytes)
#   [15]    key byte 0x00
#   [16]    version 0x04
#   [17]    padding 0x00
#   [18]    sender_type 0x2D ('-')
#   [19:59] sender_name (40 bytes: space-padded + null)
#   [59:70] 11 zero bytes
#   [70]    msg_type (0x03 = MSG_SERVER class)
#   [71]    direction (0x01 = server response)
#   [72:82] opcode_name "MSG_SERVER" (10 bytes)
#   [82:112] opcode_padding (30 space bytes)
#   [112:114] unknown 0x0000
#   [114:116] opcode_field 0x0500
#   [116:118] sub_opcode 0x0403
_SAPMS_HEADER_SIZE = 118  # wire-captured

# Per-server entry size (wire-captured: 3 entries × 160 bytes = 480 bytes payload).
_SAPMS_ENTRY_SIZE = 160  # wire-captured

# Per-server entry field offsets (relative to entry start, wire-captured):
#   [0:40]    instance_name — space-padded ASCII
#   [40:80]   hostname_string — space-padded dotted IPv4 or hostname
#   [80:120]  field3 — [ASSUMED] secondary name / padding
#   [120:135] unknown zeros
#   [135:137] 0xFFFF marker (wire-captured in all 3 entries)
#   [137:141] ip_addr_primary (4-byte BE IPv4)
#   [141:145] ip_addr_secondary (4-byte BE IPv4, duplicate)
#   [145:147] port (2-byte BE)
#   [147:160] trailing flags [ASSUMED]
_ENTRY_FFFF_OFFSET = 135  # wire-captured
_ENTRY_IP_OFFSET = 137  # wire-captured
_ENTRY_PORT_OFFSET = 145  # wire-captured


def parse_sapms_server_list(frame: bytes) -> list[tuple[str, int]]:
    """Parse a SAPMS MESSAGE server-list response frame into a list of (host, port).

    ``frame`` must include the 4-byte NI length prefix (the full TCP payload as
    delivered by the transport layer). The function validates:
      - The 4-byte NI length prefix is consistent with the buffer size (T-04-MSDOS)
      - The **MESSAGE** magic is present (T-04-MSERR / wrong-source detection)
      - Each per-server entry does not read past the end of the buffer (T-04-MSDOS)

    Returns a list of (dotted-decimal host str, port int) for each server entry.
    Entries with port 0 are included (callers choose which to use). Hosts are
    derived from the binary IP field (4-byte BE at entry offset 137) not the
    ASCII hostname string (which may be a FQDN rather than a routable address).

    Field layout confirmed from wire capture 2026-06-27 (TRANS-03):
      tests/golden/router/sapms_server_list.bin (598 bytes, 3 entries × 160 bytes).
    Semantic field annotations in tests/golden/router/sapms_server_list.json.

    Raises ValueError on magic mismatch, NI-length mismatch, or truncated entries
    (all raised as ValueError so callers can surface as CommunicationError in 04-05).
    """
    # Minimum size: header only (no entries is valid but frame must be at least header).
    if len(frame) < _SAPMS_HEADER_SIZE:
        raise ValueError(
            f"SAPMS frame too short: {len(frame)} bytes, need at least "
            f"{_SAPMS_HEADER_SIZE} bytes for header"
        )

    # Validate NI length prefix (T-04-MSDOS: declared length must match buffer).
    (ni_len,) = struct.unpack_from(">I", frame, 0)
    if ni_len != len(frame) - 4:
        raise ValueError(
            f"SAPMS frame NI length mismatch: declared {ni_len}, "
            f"buffer body is {len(frame) - 4} bytes"
        )

    # Validate magic (T-04-MSERR: wrong magic = rogue source or protocol error).
    magic = frame[4:15]
    if magic != _SAPMS_MAGIC:
        try:
            magic_str = magic.decode("ascii", "replace")
        except Exception:
            magic_str = repr(magic)
        raise ValueError(f"SAPMS frame invalid magic: expected '**MESSAGE**', got {magic_str!r}")

    # Determine how many complete 160-byte entries fit in the remaining payload.
    # [ASSUMED] the entry count is inferred from the remaining bytes rather than
    # read from a count field (no confirmed count field found in the header).
    entries_payload = len(frame) - _SAPMS_HEADER_SIZE
    if entries_payload % _SAPMS_ENTRY_SIZE != 0:
        # Frame size is not an exact multiple — it's truncated or corrupt.
        raise ValueError(
            f"SAPMS frame entry section truncated: {entries_payload} remaining bytes "
            f"is not a multiple of {_SAPMS_ENTRY_SIZE} (entry size). "
            f"Possible truncation or corrupt frame."
        )
    entry_count = entries_payload // _SAPMS_ENTRY_SIZE

    results: list[tuple[str, int]] = []
    for i in range(entry_count):
        entry_start = _SAPMS_HEADER_SIZE + i * _SAPMS_ENTRY_SIZE
        entry_end = entry_start + _SAPMS_ENTRY_SIZE
        # Bounds check: each entry must be fully within the buffer (T-04-MSDOS).
        if entry_end > len(frame):
            raise ValueError(
                f"SAPMS frame entry {i} exceeds buffer bounds: "
                f"entry [{entry_start}:{entry_end}] but buffer is {len(frame)} bytes"
            )
        # Extract binary IP (4-byte BE at entry offset _ENTRY_IP_OFFSET).
        ip_bytes = frame[entry_start + _ENTRY_IP_OFFSET : entry_start + _ENTRY_IP_OFFSET + 4]
        if len(ip_bytes) < 4:
            raise ValueError(f"SAPMS entry {i}: IP field truncated at buffer boundary")
        host = socket.inet_ntoa(ip_bytes)
        # Extract port (2-byte BE at entry offset _ENTRY_PORT_OFFSET).
        (port,) = struct.unpack_from(">H", frame, entry_start + _ENTRY_PORT_OFFSET)
        results.append((host, port))

    return results


class MessageServerClient:
    """Message-server group-logon client (TRANS-03).

    Resolves a logon group to the least-loaded application server via a
    short-lived side connection. Driven over a Transport-seam object
    (send_message/recv_message) so it is testable with MockTransport.
    """

    def __init__(self, transport: object) -> None:
        # ``transport`` is any object exposing the send_message/recv_message seam
        # (the real Transport or a MockTransport in tests).
        self._transport = transport

    def resolve(self, group: str) -> tuple[str, int]:
        """Resolve a logon ``group`` to (ashost, sysnr) over the binary protocol.

        Delegates to :meth:`resolve_full`, which runs the real SAPMS exchange.
        Until 2026-08-31 this method ran a different, invented protocol: a 2-byte
        length-prefixed group name, shaped to satisfy MockTransport and
        uninterpretable by any real message server. Two implementations of one
        thing, one of them fictional, is worse than one that reports its limits.
        """
        return self.resolve_full(group=group)

    def resolve_full(self, group: str = "", sysid: str = "") -> tuple[str, int]:
        """Resolve a logon group to (ashost, sysnr) over the binary protocol.

        The exchange, captured from SAP GUI performing a group logon and then
        reproduced against the live server by this library:

            attach   (operation 0x08)           -> reply, errorno 0
            request  (operation 0x01, sel 0x1d) -> server list as KEY=VALUE text
            detach   (operation 0x04)

        The transport seam owns the NI length prefix, so everything sent here is
        the bare SAPMS body.
        """
        self._transport.send_message(_build_sapms_login_frame())  # type: ignore[attr-defined]
        attach_reply = bytes(self._transport.recv_message())  # type: ignore[attr-defined]
        errorno, _to, _from, _mt = parse_sapms_reply(attach_reply)
        if errorno != 0:
            raise SapRfcError(
                f"message server refused the attach: {describe_ms_errorno(errorno)} "
                f"(return code {errorno})"
            )

        self._transport.send_message(_build_sapms_server_list_request())  # type: ignore[attr-defined]
        list_reply = bytes(self._transport.recv_message())  # type: ignore[attr-defined]
        stripped = list_reply[4:] if list_reply[4:16] == _SAPMS_MAGIC_FULL else list_reply
        errorno = decode_ms_errorno(stripped)
        if errorno != 0:
            raise SapRfcError(
                f"message server refused the server-list request: "
                f"{describe_ms_errorno(errorno)} (return code {errorno})"
            )
        records = parse_ms_list_reply(list_reply)

        try:
            self._transport.send_message(_build_sapms_detach_frame())  # type: ignore[attr-defined]
        except OSError:
            # Detach is a courtesy; the answer is already in hand.
            pass

        if not records:
            raise ValueError(
                f"message server returned no application server for group {group or 'PUBLIC'!r}"
            )

        # Records carry HOSTNAME and PORT. PORT is the DISPATCHER port (32<NN>),
        # not the gateway: the captured reply reads PORT=3200 for an application
        # server whose gateway is 3300. sysnr therefore comes from the dispatcher
        # formula and the caller adds 3300 (or 4800 for SNC) for RFC.
        chosen = records[0]
        ashost = chosen.get("HOSTNAME", "")
        port_text = chosen.get("PORT", "")
        if not ashost or ashost == "0.0.0.0":
            raise ValueError(
                f"message server returned an unusable application-server address "
                f"{ashost!r} — refusing to connect to an empty or unroutable host"
            )
        try:
            port = int(port_text)
        except ValueError:
            raise ValueError(
                f"message server returned a non-numeric PORT {port_text!r} for {ashost!r}"
            ) from None
        sysnr = port - 3200
        if not 0 <= sysnr <= 99:
            raise ValueError(
                f"message server returned dispatcher port {port} for {ashost!r}, which "
                f"is not 3200 + a system number (32<NN>). Connect with ashost/sysnr."
            )
        return ashost, sysnr


# ---------------------------------------------------------------------------
# SAPMS MESSAGE frame builders (wire-captured field layout, 2026-06-27)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# SAPMS MESSAGE frame builders (wire-captured field layout, 2026-06-27)
# ---------------------------------------------------------------------------


# --------------------------------------------------------------------------- #
# SAPMS binary frame — CONFIRMED against a live message server 2026-08-31
# --------------------------------------------------------------------------- #
#
# The attach frame is exactly 110 bytes (0x6e) of body behind the 4-byte NI
# length prefix. The header runs to 0x6c and ends with the 2-byte service
# number, so the header IS the whole frame — there is no body after it.
#
#   0x00  12  "**MESSAGE**\0"
#   0x0c   1  version          — 4. Sending 5 is answered with -12
#                                "invalid client version"; 1-3 get the
#                                connection dropped without a reply.
#   0x0d   1  errorno          — 0 outbound; the server's return code inbound.
#   0x0e  40  toname           — ASCII, space-padded.
#   0x36   1  msgtype          — 0 gets no reply; 1-7 are all answered.
#   0x43   1  must be 3        — 0, 1, 2 and 4 each get the connection dropped.
#   0x44  40  fromname         — ASCII, space-padded; the client's own name.
#   0x6c   2  service number   — network order.
#
# Every value above was established by sending candidate frames to a live
# message server (A4H, kernel 793, port 3601) and recording which drew a reply,
# which drew a specific error, and which were dropped. Golden fixture:
# tests/golden/router/sapms_attach_access_denied.bin.
#
# What the previous implementation sent: a 114-byte body, with 0x0e read as a
# one-byte "sender type" and a 10-byte "opcode name" placed at 0x44 — which is
# where the 40-byte fromname belongs. The message server closes the connection
# on that frame without replying at all. The mistake survived because both
# fields are space-padded, so the bytes looked plausible next to a partial
# capture.

_SAPMS_MAGIC_FULL = b"**MESSAGE**\x00"
_SAPMS_HEADER_LEN = 0x6E  # 110
_SAPMS_VERSION = 4

_OFF_VERSION = 0x0C
_OFF_ERRORNO = 0x0D
_OFF_TONAME = 0x0E
_OFF_MSGTYPE = 0x36
_OFF_FLAG = 0x42
_OFF_OPERATION = 0x43
_OFF_FROMNAME = 0x44
_OFF_SERVNO = 0x6C
_NAME_LEN = 40

# 0x42 marks which side is speaking, 0x43 selects the operation. Captured from
# SAP GUI performing a group logon (tests/golden/router/sapms_*.bin) and then
# reproduced against the live server with this library, which answered errorno 0.
_FLAG_CLIENT = 0x02
_FLAG_SERVER = 0x03

_OP_ATTACH = 0x08
_OP_REQUEST = 0x01
_OP_DETACH = 0x04

# The request body is a 4-byte opcode block followed by 48 bytes of parameters:
#   [0] opcode  [1] error  [2] opcode version  [3] 0x01 outbound / 0x03 on the reply
#
# There is more than one server-list opcode, and they carry DIFFERENT payload
# formats. Two are captured here:
#
#   0x1e version 0x01 -> KEY=VALUE text      (SAP GUI group logon, 2026-08-31)
#   0x05 version 0x04 -> binary entry table  (2026-06-27 capture)
#
# Both are genuine replies with the same 110-byte header; they differ only in the
# opcode block and the shape of what follows. parse_ms_list_reply handles the text
# form and parse_sapms_server_list the binary one — neither supersedes the other,
# so a reply is dispatched on its opcode rather than assumed.
_MS_OPCODE_TEXT = 0x1E
_MS_OPCODE_BINARY = 0x05
_OPCODE_REQUEST = bytes((_MS_OPCODE_TEXT, 0x00, 0x01, 0x01))
_OPCODE_REPLY = bytes((_MS_OPCODE_TEXT, 0x00, 0x01, 0x03))

# One byte at offset 11 of the request body selects what is being asked for.
# Both values come from the same capture: SAP GUI sends 0x1d and gets the
# application-server record, then sends 0x1f and gets the logon-group list.
_SEL_SERVER_LIST = 0x1D
_SEL_GROUP_LIST = 0x1F
_REQUEST_BODY_LEN = 52

# Message-server return codes, as the server reports them in the errorno byte.
# Confirmed live: -20 for an attach this server's ACL refuses, and -12 by sending
# version 5 deliberately. The remainder are decoded to the same scheme.
_MS_ERRORS: dict[int, str] = {
    -12: "invalid client version",
    -18: "message server shutdown",
    -20: "access denied",
    -25: "message server soft shutdown",
}


def decode_ms_errorno(body: bytes) -> int:
    """Return the signed message-server return code from a SAPMS reply.

    0 means success. The field is one signed byte at 0x0d.
    """
    if len(body) <= _OFF_ERRORNO:
        raise ValueError(f"SAPMS frame too short to hold a return code: {len(body)} bytes")
    raw = body[_OFF_ERRORNO]
    return raw - 256 if raw > 127 else raw


def describe_ms_errorno(code: int) -> str:
    """Human-readable text for a message-server return code."""
    return _MS_ERRORS.get(code, f"message server error {code}")


def build_sapms_frame(
    *,
    operation: int,
    toname: str = "-",
    fromname: str = "-",
    flag: int = _FLAG_CLIENT,
    msgtype: int = 0,
    servno: int = 0,
    version: int = _SAPMS_VERSION,
    body: bytes = b"",
) -> bytes:
    """Build a SAPMS frame body (no NI prefix — the transport adds that).

    ``operation`` is the byte at 0x43: :data:`_OP_ATTACH`, :data:`_OP_REQUEST`
    or :data:`_OP_DETACH`.
    """
    buf = bytearray(_SAPMS_HEADER_LEN)
    buf[0 : len(_SAPMS_MAGIC_FULL)] = _SAPMS_MAGIC_FULL
    buf[_OFF_VERSION] = version
    buf[_OFF_ERRORNO] = 0
    buf[_OFF_TONAME : _OFF_TONAME + _NAME_LEN] = _ms_name(toname)
    buf[_OFF_MSGTYPE] = msgtype & 0xFF
    buf[_OFF_FLAG] = flag
    buf[_OFF_OPERATION] = operation
    buf[_OFF_FROMNAME : _OFF_FROMNAME + _NAME_LEN] = _ms_name(fromname)
    struct.pack_into(">H", buf, _OFF_SERVNO, servno)
    return bytes(buf) + body


def build_ms_list_request(selector: int) -> bytes:
    """Build the body of a list request: opcode block plus 48 parameter bytes."""
    body = bytearray(_REQUEST_BODY_LEN)
    body[0:4] = _OPCODE_REQUEST
    body[4] = _FLAG_CLIENT
    body[11] = selector
    return build_sapms_frame(
        operation=_OP_REQUEST,
        toname="MSG_SERVER",
        fromname="-",
        body=bytes(body),
    )


def parse_ms_list_reply(frame: bytes) -> list[dict[str, str]]:
    """Parse a message-server list reply into one dict per record.

    The payload is plain text, not a binary entry table: newline-separated
    records of pipe-separated ``KEY=VALUE`` pairs. A server-list reply looks
    like::

        ASNAME=host_SID_00|HOSTNAME=host|PORT=3200|SAPSRV=DIA UPD BTC ...|SNC=p:CN=...

    and a group-list reply like::

        GROUP=PUBLIC|HOSTNAME=host|PORT=3200|SNC=p:CN=...

    Source: tests/golden/router/sapms_serverlist_reply.bin and
    sapms_grouplist_reply.bin, both captured from a live exchange.
    """
    body = frame[4:] if frame[4 : 4 + 12] == _SAPMS_MAGIC_FULL else frame
    if len(body) < _SAPMS_HEADER_LEN + 4:
        raise ValueError(f"SAPMS list reply too short: {len(body)} bytes")
    payload = body[_SAPMS_HEADER_LEN:]
    if payload[:4] != _OPCODE_REPLY:
        if payload and payload[0] == _MS_OPCODE_BINARY:
            raise ValueError(
                f"this is an opcode 0x{_MS_OPCODE_BINARY:02x} reply, whose payload is a "
                f"binary entry table rather than KEY=VALUE text — use "
                f"parse_sapms_server_list for that form"
            )
        raise ValueError(
            f"unexpected message-server opcode block {payload[:4].hex(' ')}, "
            f"expected {_OPCODE_REPLY.hex(' ')}"
        )
    text = payload[4:].decode("latin-1").rstrip("\x00").strip()
    records: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields: dict[str, str] = {}
        for pair in line.split("|"):
            key, sep, value = pair.partition("=")
            if sep:
                fields[key.strip()] = value.strip()
        if fields:
            records.append(fields)
    return records


def _ms_name(name: str) -> bytes:
    """A 40-byte space-padded ASCII name field."""
    return name.encode("ascii", "replace")[:_NAME_LEN].ljust(_NAME_LEN, b" ")


def parse_sapms_reply(frame: bytes) -> tuple[int, str, str, int]:
    """Parse a SAPMS reply into (errorno, toname, fromname, msgtype).

    The server swaps the names round: the name sent as ``fromname`` comes back in
    ``toname``. Confirmed against the live reply in the golden fixture.
    """
    body = frame[4:] if len(frame) > 4 and frame[4 : 4 + 12] == _SAPMS_MAGIC_FULL else frame
    if len(body) < _SAPMS_HEADER_LEN:
        raise ValueError(f"SAPMS reply is {len(body)} bytes, expected at least {_SAPMS_HEADER_LEN}")
    if body[: len(_SAPMS_MAGIC_FULL)] != _SAPMS_MAGIC_FULL:
        raise ValueError(f"not a SAPMS frame: magic is {body[:12]!r}")
    return (
        decode_ms_errorno(body),
        body[_OFF_TONAME : _OFF_TONAME + _NAME_LEN].decode("ascii", "replace").rstrip(),
        body[_OFF_FROMNAME : _OFF_FROMNAME + _NAME_LEN].decode("ascii", "replace").rstrip(),
        body[_OFF_MSGTYPE],
    )


def _build_sapms_login_frame(group: str = "", sysid: str = "") -> bytes:
    """Build the SAPMS attach frame body.

    Operation 0x08 with flag 0x02, exactly as captured from SAP GUI. The server
    replies with the same frame carrying errorno 0 and fromname "MSG_SERVER".
    """
    return build_sapms_frame(operation=_OP_ATTACH, toname="-", fromname="-")


def _build_sapms_server_list_request() -> bytes:
    """Build the server-list request body (selector 0x1d)."""
    return build_ms_list_request(_SEL_SERVER_LIST)


def _build_sapms_group_list_request() -> bytes:
    """Build the logon-group list request body (selector 0x1f)."""
    return build_ms_list_request(_SEL_GROUP_LIST)


def _build_sapms_detach_frame() -> bytes:
    """Build the detach frame body (operation 0x04)."""
    return build_sapms_frame(operation=_OP_DETACH, toname="-", fromname="-")


# --------------------------------------------------------------------------- #
# Message server HTTP interface (evidence tier 1 — live capture 2026-08-31)
# --------------------------------------------------------------------------- #
#
# The message server also answers over HTTP, and that interface is documented,
# line-oriented, and needs no reverse engineering. The binary protocol above is
# still built from a partial capture: against a live message server on A4H it
# accepts the connection and then answers nothing, so the [ASSUMED] login frame
# and opcode pair are wrong. Until a capture fixes them, this is the path that
# actually resolves a load-balanced logon.
#
# Captured responses are in tests/golden/router/ms_http_*.txt.
#
#   /msgserver/text/logon?version=1.2[&group=NAME]
#       version 1.2
#       <instance name>
#       RFC<TAB><host><TAB><port><TAB><extra>
#       ... one line per service (DIAG, DIAGS, RFC, RFCS, HTTP, HTTPS)
#
#   /msgserver/text/lglist
#       version 1.0
#       <group><TAB><host><TAB><port><TAB><load or release>
#
# The port is 8100 + the message server's instance number, NOT the application
# server's system number — see _ms_http_port in connection.py.

_MS_HTTP_TIMEOUT = 10.0


class MessageServerHttpError(SapRfcError):
    """The message server's HTTP interface could not be reached or understood."""


def parse_ms_http_logon(body: str) -> list[tuple[str, str, int, str]]:
    """Parse ``/msgserver/text/logon`` into (service, host, port, extra) rows.

    Source: tests/golden/router/ms_http_logon_v12.txt. Tab-separated, one row per
    service; the first two lines are the format version and the instance name.
    Rows that do not parse are skipped rather than failing the whole response —
    the service list is open-ended and a future release adding a row must not
    break resolution of the RFC row we came for.
    """
    rows: list[tuple[str, str, int, str]] = []
    for line in body.splitlines()[2:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            port = int(parts[2].strip())
        except ValueError:
            continue
        extra = parts[3].strip() if len(parts) > 3 else ""
        rows.append((parts[0].strip(), parts[1].strip(), port, extra))
    return rows


def parse_ms_http_lglist(body: str) -> list[tuple[str, str, int]]:
    """Parse ``/msgserver/text/lglist`` into (group, host, port) rows.

    Source: tests/golden/router/ms_http_lglist.txt.
    """
    groups: list[tuple[str, str, int]] = []
    for line in body.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            groups.append((parts[0].strip(), parts[1].strip(), int(parts[2].strip())))
        except ValueError:
            continue
    return groups


def resolve_rfc_server_http(
    mshost: str,
    http_port: int,
    *,
    group: str | None = None,
    timeout: float = _MS_HTTP_TIMEOUT,
) -> tuple[str, int]:
    """Resolve the RFC (host, port) for a logon group via the message server's HTTP API.

    Returns the ``RFC`` service row, which is the plaintext RFC endpoint — not
    ``RFCS``, which is the SNC-protected one and needs SNC parameters the caller
    has not necessarily supplied.

    Raises:
        MessageServerHttpError: the interface is unreachable, or answers without
            an RFC row. Both are reported rather than falling back to a guess:
            connecting to the wrong application server is not a failure the
            caller can see.
    """
    url = f"http://{mshost}:{http_port}/msgserver/text/logon?version=1.2"
    if group:
        url += f"&group={quote(group)}"
    try:
        with urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed http scheme
            body = response.read().decode("utf-8", "replace")
    except (OSError, ValueError) as exc:
        raise MessageServerHttpError(
            f"message server HTTP interface at {mshost}:{http_port} is unreachable "
            f"({type(exc).__name__}: {exc}). It is only present when the profile sets "
            f"ms/server_port_0; pass ashost/sysnr directly if it is not enabled."
        ) from exc

    rows = parse_ms_http_logon(body)
    for service, host, port, _extra in rows:
        if service == "RFC":
            return host, port
    available = ", ".join(sorted({row[0] for row in rows})) or "none"
    raise MessageServerHttpError(
        f"message server at {mshost}:{http_port} listed no RFC service"
        + (f" for group {group!r}" if group else "")
        + f" (services offered: {available})"
    )
