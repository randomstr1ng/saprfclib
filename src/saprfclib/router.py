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

# NI_ROUTE control marker. The 8-byte NI control-message family (framing.md
# lines 92-102) includes NI_RTERR / NI_ROUTE; the exact NI_ROUTE entry layout
# below is [ASSUMED].
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

    def resolve_full(self, group: str, sysid: str = "") -> tuple[str, int]:
        """Resolve a logon ``group`` to (ashost, sysnr) using the full SAPMS MESSAGE
        exchange and parse_sapms_server_list (TRANS-03, Plan 04-03).

        Exchange sequence (wire-captured 2026-06-27, TRANS-03):
          1. Send SAPMS login frame (14-byte simple opcode frame)
          2. Receive login ack (validated for **MESSAGE** magic)
          3. Send SAPMS server-list request frame (opcode MSG_SERVER / 0x0500)
          4. Receive server-list response → parse_sapms_server_list → select server

        The first entry with a non-zero port is selected as the active server.
        Round-robin / load-weighted selection across multiple active servers is
        deferred to Phase 5 (connection pool). sysnr = (port - 3200) // 100.

        Raises ValueError on protocol errors, malformed frames, or invalid redirect
        targets (T-04-REDIR: host/sysnr bounds validated before return).
        """
        # Step 1: send login frame. Wire-captured opcode: msg_type=0x02, direction=0x08.
        # [ASSUMED] minimal login frame is sufficient for MockTransport tests; the real
        # live exchange uses the full multi-frame AD-EYECATCH handshake (capture lines
        # 40-88 in phase03_msgserver_capture_output.txt). For the Phase 4 MVP the
        # full live path is exercised by the integration test; the unit test uses
        # MockTransport scripted with [login_ack, server_list_response].
        # The transport seam is NI-framed: send_message adds the 4-byte length
        # prefix and recv_message strips it, so everything here is the bare SAPMS
        # body. This used to send frames that already carried a prefix — the
        # transport then added a second one — and to look for the magic at offset
        # 4 of a payload whose prefix had already been removed. Both mistakes
        # cancelled out under MockTransport, whose scripted frames included the
        # prefix, and neither could have worked on a socket.
        self._transport.send_message(  # type: ignore[attr-defined]
            _build_sapms_login_frame(group=group, sysid=sysid)
        )

        # Step 2: receive the attach reply and report the server's own return code.
        login_ack = bytes(self._transport.recv_message())  # type: ignore[attr-defined]
        errorno, _toname, _fromname, _msgtype = parse_sapms_reply(login_ack)
        if errorno != 0:
            raise SapRfcError(
                f"message server refused the attach: {describe_ms_errorno(errorno)} "
                f"(return code {errorno}). An external attach has to be permitted by "
                f"the server; that is governed by ms/acl_info. The HTTP interface "
                f"needs no attach — see docs/protocol/message_server.md."
            )

        # Step 3: send the server-list request.
        #
        # [ASSUMED] which msgtype asks for a server list. Every attach against a
        # live server so far has been refused before this point, so no request has
        # ever been answered with a list to compare against.
        self._transport.send_message(  # type: ignore[attr-defined]
            _build_sapms_server_list_request()
        )

        # Step 4: receive server-list response and parse.
        server_list_frame = self._transport.recv_message()  # type: ignore[attr-defined]
        entries = parse_sapms_server_list(server_list_frame)

        # Select the first entry with a non-zero port (active server).
        selected: tuple[str, int] | None = None
        for host, port in entries:
            if port > 0:
                selected = (host, port)
                break
        if selected is None:
            raise ValueError(
                f"SAPMS server-list: no active server found (all entries have port 0). "
                f"Entries: {entries!r}"
            )

        ashost, port = selected
        sysnr = (port - 3200) // 100

        # T-04-REDIR: validate the resolved target before returning.
        if not ashost or ashost == "0.0.0.0":
            raise ValueError(
                f"SAPMS redirect: invalid application-server address {ashost!r} — "
                f"refusing to connect to empty or unroutable host"
            )
        if not 0 <= sysnr <= 99:
            raise ValueError(
                f"SAPMS redirect: sysnr {sysnr} out of range 0-99 "
                f"(derived from port {port}: (port - 3200) // 100 = {sysnr})"
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
_SAPMS_FRAME_LEN = 0x6E  # 110 — confirmed: the SDK writes exactly this many
_SAPMS_VERSION = 4
_SAPMS_FLAG_43 = 3  # confirmed mandatory; any other value drops the connection

_OFF_VERSION = 0x0C
_OFF_ERRORNO = 0x0D
_OFF_TONAME = 0x0E
_OFF_MSGTYPE = 0x36
_OFF_FLAG43 = 0x43
_OFF_FROMNAME = 0x44
_OFF_SERVNO = 0x6C
_NAME_LEN = 40

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
    msgtype: int,
    toname: str = "-",
    fromname: str = "-",
    servno: int = 0,
    version: int = _SAPMS_VERSION,
) -> bytes:
    """Build a SAPMS frame with its NI length prefix (114 bytes total).

    Defaults match what the SDK's attach path sends: ``"-"`` for a name the
    caller has not set, and service number 0 when none applies.
    """
    body = bytearray(_SAPMS_FRAME_LEN)
    body[0 : len(_SAPMS_MAGIC_FULL)] = _SAPMS_MAGIC_FULL
    body[_OFF_VERSION] = version
    body[_OFF_ERRORNO] = 0
    body[_OFF_TONAME : _OFF_TONAME + _NAME_LEN] = _ms_name(toname)
    body[_OFF_MSGTYPE] = msgtype & 0xFF
    body[_OFF_FLAG43] = _SAPMS_FLAG_43
    body[_OFF_FROMNAME : _OFF_FROMNAME + _NAME_LEN] = _ms_name(fromname)
    struct.pack_into(">H", body, _OFF_SERVNO, servno)
    return struct.pack(">I", len(body)) + bytes(body)


def _ms_name(name: str) -> bytes:
    """A 40-byte space-padded ASCII name field."""
    return name.encode("ascii", "replace")[:_NAME_LEN].ljust(_NAME_LEN, b" ")


def parse_sapms_reply(frame: bytes) -> tuple[int, str, str, int]:
    """Parse a SAPMS reply into (errorno, toname, fromname, msgtype).

    The server swaps the names round: the name sent as ``fromname`` comes back in
    ``toname``. Confirmed against the live reply in the golden fixture.
    """
    body = frame[4:] if len(frame) > 4 and frame[4 : 4 + 12] == _SAPMS_MAGIC_FULL else frame
    if len(body) < _SAPMS_FRAME_LEN:
        raise ValueError(f"SAPMS reply is {len(body)} bytes, expected at least {_SAPMS_FRAME_LEN}")
    if body[: len(_SAPMS_MAGIC_FULL)] != _SAPMS_MAGIC_FULL:
        raise ValueError(f"not a SAPMS frame: magic is {body[:12]!r}")
    return (
        decode_ms_errorno(body),
        body[_OFF_TONAME : _OFF_TONAME + _NAME_LEN].decode("ascii", "replace").rstrip(),
        body[_OFF_FROMNAME : _OFF_FROMNAME + _NAME_LEN].decode("ascii", "replace").rstrip(),
        body[_OFF_MSGTYPE],
    )


def _build_sapms_login_frame(group: str = "", sysid: str = "") -> bytes:
    """Build a SAPMS attach frame (110-byte body + 4-byte NI prefix).

    ``msgtype=1`` is used: 0 draws no reply at all, while 1 through 7 are each
    answered. Which of them the server treats as a logon-group query is not yet
    established — this server refuses the attach with "access denied" before
    getting that far, so the distinction has not been observable here.
    """
    return build_sapms_frame(
        msgtype=1,
        toname="-",
        fromname=sysid or "-",
    )[4:]  # body only: the transport adds the NI length prefix


def _build_sapms_server_list_request() -> bytes:
    """Build a SAPMS server-list request frame.

    The frame is structurally valid — same 110-byte layout as the attach, which a
    live message server parses and answers. What is NOT established is which
    ``msgtype`` asks for a server list: this server refuses the attach that
    precedes it with "access denied", so no request has ever been answered with
    a list to compare against.

    ``msgtype=4`` is a placeholder, not a finding. Do not read it as one.
    """
    # body only: the transport adds the NI length prefix
    return build_sapms_frame(msgtype=4, toname="-", fromname="-")[4:]


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
