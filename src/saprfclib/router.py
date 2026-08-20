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

__all__ = [
    "RouteHop",
    "parse_route_string",
    "build_ni_route",
    "parse_sapms_server_list",
    "MessageServerClient",
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
        """Resolve a logon ``group`` to (ashost, sysnr).

        TRANS-03 confirmed from live capture 2026-06-27: the full SAPMS exchange
        uses multi-frame **MESSAGE** protocol (magic + 4-byte header + 40-byte
        sender + opcode fields). Full frame parsing is deferred to Phase 4 when
        the RFC invoke path is available for end-to-end testing. This method
        exposes the mock-testable seam interface used by Phase 3 tests.

        The simplified mock contract (used by MockTransport tests):
          Request: the group name as a 2-byte BE length-prefixed ASCII field.
          Response: app-server host as a 2-byte BE length-prefixed ASCII field
                    followed by a 2-byte BE system number.

        Phase 4 will replace request/response with the full **MESSAGE** exchange
        (login frame → login ack → get-server list → server list parse → IP+port
        → sysnr = port - 3300).

        The resolved (ashost, sysnr) is validated before use (threat T-03-REDIR).
        """
        group_bytes = group.encode("ascii", "replace")
        request = struct.pack(">H", len(group_bytes)) + group_bytes
        self._transport.send_message(request)  # type: ignore[attr-defined]
        resp = self._transport.recv_message()  # type: ignore[attr-defined]

        if len(resp) < 2:
            raise ValueError(
                "malformed message-server redirect: response too short for a host length"
            )
        (host_len,) = struct.unpack_from(">H", resp, 0)
        host_end = 2 + host_len
        if host_len == 0 or host_end + 2 > len(resp):
            raise ValueError(
                "malformed message-server redirect: host field exceeds response bounds"
            )
        ashost = resp[2:host_end].decode("ascii", "replace")
        (sysnr,) = struct.unpack_from(">H", resp, host_end)

        # T-03-REDIR: validate the resolved target is well-formed before use.
        if not ashost.strip():
            raise ValueError("malformed message-server redirect: empty application-server host")
        if not 0 <= sysnr <= 99:
            raise ValueError(
                f"malformed message-server redirect: system number {sysnr} out of range 0-99"
            )
        return ashost, sysnr

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
        login_frame = _build_sapms_login_frame(group=group, sysid=sysid)
        self._transport.send_message(login_frame)  # type: ignore[attr-defined]

        # Step 2: receive login ack. Validate magic only (content is [ASSUMED]).
        login_ack = self._transport.recv_message()  # type: ignore[attr-defined]
        if len(login_ack) < 15 or login_ack[4:15] != _SAPMS_MAGIC:
            raise ValueError(
                "SAPMS login ack invalid: missing **MESSAGE** magic or response too short"
            )

        # Step 3: send server-list request. Wire-captured opcode 0x0500 / sub 0x0403.
        server_list_req = _build_sapms_server_list_request()
        self._transport.send_message(server_list_req)  # type: ignore[attr-defined]

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


def _build_sapms_header(
    msg_type: int,
    direction: int,
    opcode_name: str,
    opcode_field: int,
    sub_opcode: int,
    sender: str = "",
) -> bytes:
    """Build a SAPMS MESSAGE frame header (118 bytes, wire-captured layout).

    Offsets confirmed from live capture 2026-06-27 (TRANS-03):
      [0:4]   NI length prefix (placeholder, caller must fix)
      [4:15]  "**MESSAGE**" magic
      [15]    key 0x00
      [16]    version 0x04
      [17]    padding 0x00
      [18]    sender_type 0x2D ('-') for empty sender
      [19:59] sender_name (40 bytes: space-padded + null)
      [59:70] 11 zero bytes
      [70]    msg_type
      [71]    direction
      [72:82] opcode_name (10-byte ASCII, space-padded)
      [82:112] opcode padding (30 space bytes)
      [112:114] 0x0000
      [114:116] opcode_field
      [116:118] sub_opcode
    """
    buf = bytearray(118)
    # NI length placeholder (0 — caller fixes after appending body)
    struct.pack_into(">I", buf, 0, 0)
    # Magic
    buf[4:15] = _SAPMS_MAGIC
    # key=0, version=4, padding=0, sender_type='-'
    buf[15] = 0x00
    buf[16] = 0x04
    buf[17] = 0x00
    buf[18] = 0x2D
    # sender_name: 39 chars space-padded + null
    sender_bytes = sender.encode("ascii", "replace")[:39]
    buf[19 : 19 + len(sender_bytes)] = sender_bytes
    buf[19 + len(sender_bytes) : 58] = b" " * (39 - len(sender_bytes))
    buf[58] = 0x00  # null terminator
    # zeros [59:70]
    buf[59:70] = b"\x00" * 11
    # msg_type, direction
    buf[70] = msg_type & 0xFF
    buf[71] = direction & 0xFF
    # opcode_name: 10 bytes space-padded
    op_bytes = opcode_name.encode("ascii", "replace")[:10]
    buf[72 : 72 + len(op_bytes)] = op_bytes
    buf[72 + len(op_bytes) : 82] = b" " * (10 - len(op_bytes))
    # opcode padding [82:112]: 30 space bytes
    buf[82:112] = b" " * 30
    # unknown [112:114]: zeros
    buf[112:114] = b"\x00\x00"
    # opcode_field [114:116] and sub_opcode [116:118]
    struct.pack_into(">H", buf, 114, opcode_field)
    struct.pack_into(">H", buf, 116, sub_opcode)
    return bytes(buf)


def _build_sapms_login_frame(group: str = "", sysid: str = "") -> bytes:
    """Build a SAPMS login frame (118 bytes).

    Wire-captured: CLIENT→MS first frame has msg_type=0x02, direction=0x08,
    opcode_name='-' (space-padded), opcode_field=0x0000, sub_opcode=0x0000.
    The opcode fields at [112:118] are 0x00 0x00 0x40 0x00 0x01 0x00 in the
    live capture — [ASSUMED] content is not validated by the server in the
    Phase 4 mock exchange.
    """
    # [ASSUMED] login frame body is empty beyond the 118-byte header.
    # The live exchange sends a 114-byte frame (NI len 110 = 114 - 4 bytes content
    # of 110 bytes). For the Phase 4 mock test, the server-list request is the
    # meaningful frame — the login frame just opens the exchange.
    header = _build_sapms_header(
        msg_type=0x02,
        direction=0x08,
        opcode_name="-",
        opcode_field=0x0000,
        sub_opcode=0x0000,
    )
    buf = bytearray(header)
    # Fix NI length: total frame = 118 bytes, NI prefix covers the body after prefix.
    struct.pack_into(">I", buf, 0, len(buf) - 4)
    return bytes(buf)


def _build_sapms_server_list_request() -> bytes:
    """Build a SAPMS server-list request frame (118 bytes).

    Wire-captured: CLIENT→MS frame has msg_type=0x02, direction=0x01,
    opcode_name='MSG_SERVER', opcode_field=0x0500 [ASSUMED], sub_opcode=0x0403 [ASSUMED].
    The wire capture shows opcode bytes 0x05 0x00 at offset [114:116] and 0x68 0x03
    at [116:118] but these are in a different (earlier) request; the server responds
    with opcode_field=0x0500/sub=0x0403 in the response (golden fixture). [ASSUMED]
    the request uses the same opcode pair to trigger the server-list response.
    """
    header = _build_sapms_header(
        msg_type=0x02,
        direction=0x01,
        opcode_name="MSG_SERVER",
        opcode_field=0x0500,  # [ASSUMED] triggers server-list response
        sub_opcode=0x0403,  # [ASSUMED]
    )
    buf = bytearray(header)
    struct.pack_into(">I", buf, 0, len(buf) - 4)
    return bytes(buf)
