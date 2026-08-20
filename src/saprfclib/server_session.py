# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — sans-I/O RFC server session state machine (no sockets)
#
# Pure state machine mirroring session.py for the SERVER direction: a Python
# process registering a PROGRAM_ID with an SAP gateway (RfcRegisterServer) and
# then listening for inbound RFC calls the gateway pushes (RfcListenAndDispatch).
# Inputs are bytes from the Transport seam; outputs are the next bytes to send +
# state transitions. Testable against the live-captured golden fixtures in
# tests/golden/framing/ with ZERO network (the socket-free boundary is the same
# substitution point session.py uses).
#
# Requirements: SERVER-02 (gateway registration frame). Every reproduced byte is
# sourced from docs/protocol/framing.md and cross-checked against the
# server_registration_request.bin golden fixture. NO guessed bytes.
#
# KEY finding: the on-wire registration request is the SAME 0x0601 GW_CONNECT
# APPCHDR6 frame the client emits, and it is
# program_id-INDEPENDENT — the PROGRAM_ID (tpname) does NOT appear in this frame
# in any encoding. The "NWRFC" string at payload offset 48 is the fixed partner
# LU name, not the PROGRAM_ID. The tpname is conveyed to the gateway by the
# follow-up accept exchange. build_*
# therefore accepts program_id/gwserv (to match the public RfcRegisterServer
# signature and to drive state) but reproduces the program_id-independent connect
# frame; session-specific bytes (handle, IP/host/service, OS user, time() blob)
# are left zero and are skipped by compare_bytes (annotated `variable`).
#
# States (RESEARCH Pattern 2):
#   DISCONNECTED -> CONNECTED -> NI_VERSIONED -> GW_CONNECTED
#                -> REGISTERED -> LISTENING -> IN_CALL
#
# Inbound TLV from the gateway is peer-influenced and untrusted (threat
# T-05-S02): parse only with the bounds-checked walker reused from session.py.
from __future__ import annotations

import enum
import struct

from saprfclib.connection import (
    _GW_FLAGS,
    _GW_TYPE_CONNECT,
    _GW_VERSION,
)
from saprfclib.session import Session

__all__ = ["ServerSession", "ServerSessionState"]


# --------------------------------------------------------------------------- #
# Registration-frame wire constants — all sourced from docs/protocol/framing.md
# §"Server registration & inbound dispatch" (analysis + capture). The frame is the
# 0x0601 GW_CONNECT built by the gateway connect call/the GW_CONNECT builder; offsets below are payload
# offsets (NI 4-byte length header NOT included — added by _ni_frame()).
# --------------------------------------------------------------------------- #
_NI_HEADER = struct.Struct(">I")  # 4-byte big-endian NI length prefix (NiIWrite)

# Captured registration request payload length (the registration builder/the gateway connect call GW_CONNECT).
# Wire-captured server_registration_request.bin = 457B file = 4B NI + 453B payload.
_REG_PAYLOAD_LEN = 453

# APPCHDR6 / the GW_CONNECT builder fixed fields (protocol analysis; see docs/protocol/framing.md GW
# common table + GW_CONNECT_REQUEST table). Payload offsets:
_OFF_B10 = 10  # the GW_CONNECT builder *(r13_11+0x5a) init = 0x01
_OFF_B16 = 16  # the GW_CONNECT builder *(r13_11+0x60) |= 0x80 + CONV_PROTO 0x40 = 0xC0
_OFF_B21 = 21  # the GW_CONNECT builder *(r13_11+0x65) |= 4 (standard client) = 0x04
_OFF_LU_NAME = 48  # UtilCpyUcToNet partner LU name (8 bytes, net/ASCII)
_OFF_B73 = 73  # the GW_CONNECT builder *(r13_11+0x99) = 1
_OFF_MARKER = 76  # request marker [76:80]: 0x0000 then 0xFFFF (request)

_LU_PARTNER_NAME = b"NWRFC   "  # 8-byte partner LU name (fixed; docs/protocol/framing.md)
_REG_MARKER_REQUEST = b"\x00\x00\xff\xff"  # payload[76:80] request; ACK flips [78:80]->0004

# Registration-ACK detection: the gateway echoes the 0x0601 type and flips the
# tail marker low word to 0x0004 (payload[78:80]) + fills the handle [40:48].
_GW_TYPE_DONE_LOW = 0x04


class ServerSessionState(enum.Enum):
    """RFC server session lifecycle (RESEARCH Pattern 2)."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTED = "CONNECTED"
    NI_VERSIONED = "NI_VERSIONED"
    GW_CONNECTED = "GW_CONNECTED"
    REGISTERED = "REGISTERED"
    LISTENING = "LISTENING"
    IN_CALL = "IN_CALL"


class ServerSession:
    """Sans-I/O RFC server session state machine (no sockets).

    Usage (driven by the Transport seam):

        sess = ServerSession()
        transport.send(sess.build_registration_frame(program_id, gwserv))
        sess.feed(transport.recv())   # registration ACK -> REGISTERED
        sess.mark_listening()         # ready to accept inbound calls

    ``build_registration_frame`` produces the NI-framed 0x0601 GW_CONNECT
    registration request (SERVER-02). ``feed`` consumes one gateway frame and
    advances the state machine; it returns the next bytes to send (``b""`` when
    none). State guards reject out-of-order feeds, mirroring ``Session``.
    """

    def __init__(self) -> None:
        self._state = ServerSessionState.DISCONNECTED
        self._program_id: str | None = None
        self._gwserv: str | None = None
        self._handle: bytes | None = None  # gateway-assigned conn handle (from ACK)
        self._ack_tail: bytes = b"\x00\x00"  # ACK[78:80] — used in REG_WAITING[78:80]

    # ----------------------------------------------------------------- #
    # Public read-only surface
    # ----------------------------------------------------------------- #
    @property
    def state(self) -> ServerSessionState:
        return self._state

    @property
    def handle(self) -> bytes | None:
        """8-byte ASCII gateway connection handle, set after the registration ACK."""
        return self._handle

    @property
    def ack_tail(self) -> bytes:
        """2-byte ACK[78:80] connection counter — echoed in REG_WAITING[78:80]."""
        return self._ack_tail

    # ----------------------------------------------------------------- #
    # Registration frame builder (SERVER-02) — RE-gated, no guessed bytes
    # ----------------------------------------------------------------- #
    def build_registration_frame(self, program_id: str, gwserv: str) -> bytes:
        """Build the NI-framed 0x0601 GW_CONNECT registration request.

        Reproduces the program_id-INDEPENDENT connect frame exactly per
        docs/protocol/framing.md (the GW_CONNECT frame builder). ``program_id``
        and ``gwserv`` are recorded to drive state and match the public
        ``RfcRegisterServer(program_id, gwserv)`` signature, but the PROGRAM_ID is
        NOT embedded in this frame (it is sent by the follow-up accept step,
        Wave 2). Session-specific bytes (connection handle, local IP/host/service,
        OS user, ``time()`` blob) are left zero — they are emitted by the live
        Transport facade and are annotated ``variable`` in the golden sidecar.

        the registration builder validation is enforced defensively: PROGRAM_ID must
        be non-empty, ≤64 chars, and contain no ``*``; gwserv must be non-empty.
        """
        if not program_id:
            raise ValueError("program_id (tpname) must be non-empty")
        if len(program_id) > 0x40:
            raise ValueError(f"program_id (tpname) too long: {len(program_id)} > 64 chars")
        if "*" in program_id:
            raise ValueError("program_id (tpname) must not contain '*'")
        if not gwserv:
            raise ValueError("gwserv must be non-empty")

        self._program_id = program_id
        self._gwserv = gwserv

        payload = bytearray(_REG_PAYLOAD_LEN)
        # APPCHDR6 header (GW common table + GW_CONNECT_REQUEST):
        struct.pack_into(">H", payload, 0, _GW_TYPE_CONNECT)  # [0:2] 0x0601
        struct.pack_into(">H", payload, 2, _GW_VERSION)  # [2:4] 0x0200
        struct.pack_into(">I", payload, 4, _GW_FLAGS)  # [4:8] 0xFFFF0000
        payload[_OFF_B10] = 0x01  # [10]  the GW_CONNECT builder init
        payload[_OFF_B16] = 0xC0  # [16]  |=0x80 + 0x40
        payload[_OFF_B21] = 0x04  # [21]  standard client
        # [40:48] connection handle: 8 spaces on the outbound connect (the GW_CONNECT builder
        # strncpy "        "). Left zero here — annotated `variable` (the live
        # facade writes the spaces); compare_bytes skips it.
        payload[_OFF_LU_NAME : _OFF_LU_NAME + len(_LU_PARTNER_NAME)] = _LU_PARTNER_NAME
        payload[_OFF_B73] = 0x01  # [73]  the GW_CONNECT builder
        payload[_OFF_MARKER : _OFF_MARKER + 4] = _REG_MARKER_REQUEST  # [76:80]

        self._state = ServerSessionState.GW_CONNECTED
        return self._ni_frame(bytes(payload))

    @staticmethod
    def _ni_frame(payload: bytes) -> bytes:
        """Prepend the 4-byte big-endian NI length header (NiIWrite bswap)."""
        return _NI_HEADER.pack(len(payload)) + payload

    # ----------------------------------------------------------------- #
    # Drive
    # ----------------------------------------------------------------- #
    def feed(self, data: bytes) -> bytes:
        """Feed one gateway frame; advance state; return next bytes to send (b"").

        In GW_CONNECTED this consumes the registration ACK (-> REGISTERED). In
        LISTENING it surfaces an inbound RFC call frame to the dispatcher: the
        state advances LISTENING -> IN_CALL and the bounded TLV body is returned
        for ``RfcServer.dispatch_inbound`` to deserialize (the server core owns the
        codec; the session only frames + guards state). ``mark_listening_again``
        returns the machine to LISTENING once the reply has been sent.
        """
        buf = bytes(data)
        if self._state is ServerSessionState.GW_CONNECTED:
            return self._handle_registration_ack(buf)
        if self._state is ServerSessionState.LISTENING:
            return self._handle_inbound_call(buf)
        raise ValueError(f"unexpected feed in state {self._state}")

    def _handle_inbound_call(self, data: bytes) -> bytes:
        """Surface one inbound RFC call body (LISTENING -> IN_CALL).

        The gateway pushes a GW data frame (NI-framed). We strip the 4-byte NI
        length header defensively (untrusted peer bytes, T-05-S02) and hand the
        remaining payload to the server core; the GW header strip + bounds-checked
        TLV walk happen there (``RfcServer.dispatch_inbound`` ->
        ``connection._strip_gw_header`` -> invoke walkers). The session does NOT
        parse TLV itself — it only frames and guards state.
        """
        if len(data) < 4:
            raise ValueError(f"inbound call frame too short: {len(data)} bytes")
        ni_len = struct.unpack_from(">I", data, 0)[0]
        payload = data[4:]
        if ni_len != len(payload):
            raise ValueError(f"inbound call NI length {ni_len} != payload {len(payload)}")
        self._state = ServerSessionState.IN_CALL
        return payload

    def build_post_reg_a(self, gw_ip: str) -> bytes:
        """Build the 0x060f post-registration handshake frame (GW payload, not NI-framed).

        Sent immediately after consuming the REGISTER_TP ACK. Echoes the gateway-
        assigned session handle and embeds the gateway IP. Sourced from pcap MSG5
        (server_registration.pcap, stream C→S 228B, 0x060F type).

        Byte-exact offsets verified against pcap hex dump:
          [0:2]   = 06 0f (type)
          [8:12]  = 00 00 01 00 (fixed counter)
          [22]    = 0x90 (= 144 = data payload length after 80B header)
          [25]    = 0x04 (fixed field)
          [40:48] = handle (8 bytes, from REGISTER_TP ACK payload[40:48])
          [48:56] = GW IP first 8 chars, space-padded
          [56:60] = GW IP string length (BE uint32)
          [76:78] = 0xFFFF (request marker)
          [78:80] = ack_tail from REGISTER_TP ACK
          [80:80+ip_len] = full GW IP string; [80+ip_len:208] spaces; [208:224] zeros
        """
        handle = self._handle or b"        "
        ip_enc = gw_ip.encode("ascii")
        ip_len = len(ip_enc)
        ip_first8 = (ip_enc[:8]).ljust(8, b" ")

        payload = bytearray(224)
        payload[0:2] = b"\x06\x0f"
        payload[2:4] = b"\x02\x00"
        payload[4:6] = b"\xff\xff"
        payload[8:12] = b"\x00\x00\x01\x00"  # pcap MSG5[8:12]
        # pcap MSG5[22]=0x90 (data len 144), MSG5[25]=0x04
        struct.pack_into(">I", payload, 20, 0x00009000)  # [20:24] → [22]=0x90
        struct.pack_into(">I", payload, 24, 0x00040000)  # [24:28] → [25]=0x04
        payload[40:48] = handle
        payload[48:56] = ip_first8
        struct.pack_into(">I", payload, 56, ip_len)
        payload[76:78] = b"\xff\xff"
        payload[78:80] = self._ack_tail
        payload[80 : 80 + ip_len] = ip_enc
        payload[80 + ip_len : 208] = b"\x20" * (208 - 80 - ip_len)
        return bytes(payload)

    def build_post_reg_b(self) -> bytes:
        """Build the 0x0605 post-registration handshake frame (GW payload, not NI-framed).

        Sent immediately after build_post_reg_a. Sourced from pcap MSG6.

        Byte-exact offsets verified against pcap hex dump:
          [0:2]   = 06 05 (type)
          [28:32] = 00 00 01 00 (fixed counter — pcap MSG6[28:32])
          [40:48] = handle
          [76:78] = 0xFFFF (request marker)
          [78:80] = ack_tail from REGISTER_TP ACK
        """
        handle = self._handle or b"        "
        payload = bytearray(80)
        payload[0:2] = b"\x06\x05"
        payload[2:4] = b"\x02\x00"
        payload[4:6] = b"\xff\xff"
        payload[28:32] = b"\x00\x00\x01\x00"
        payload[40:48] = handle
        payload[76:78] = b"\xff\xff"
        payload[78:80] = self._ack_tail
        return bytes(payload)

    def _handle_registration_ack(self, data: bytes) -> bytes:
        """Consume the gateway registration ACK (0x0601, tail flipped to ..0004).

        ``data`` is the raw GW payload returned by Transport.recv_message() — the
        4-byte NI length header has already been consumed. The ACK fills the 8-byte
        connection handle at GW payload[40:48]; we extract it here.
        """
        # data is the raw GW payload (Transport.recv_message strips the NI header).
        if len(data) < 80:
            raise ValueError(f"registration ACK GW payload too short: {len(data)} < 80")
        # Handle at GW payload[40:48] (gateway-assigned ASCII, e.g. b"36964135").
        self._handle = data[40:48]
        # protocol analysis: REG_WAITING[78:80] = rol.w(*(arg2+0x1c), 8).
        # Empirically: *(arg2+0x1c) is populated from ACK[78:80] by the gateway connect call.
        self._ack_tail = bytes(data[78:80])
        self._state = ServerSessionState.REGISTERED
        return b""

    # ----------------------------------------------------------------- #
    # State guards (mirror session.py _require_state / mark_*)
    # ----------------------------------------------------------------- #
    def _require_state(self, *allowed: ServerSessionState) -> None:
        if self._state not in allowed:
            raise ValueError(
                f"operation not allowed in state {self._state.value!r}; "
                f"requires one of {[s.value for s in allowed]}"
            )

    def mark_listening(self) -> None:
        """REGISTERED -> LISTENING once the server is ready to accept inbound calls."""
        self._require_state(ServerSessionState.REGISTERED)
        self._state = ServerSessionState.LISTENING

    def mark_in_call(self) -> None:
        """LISTENING -> IN_CALL for the duration of one inbound dispatch."""
        self._require_state(ServerSessionState.LISTENING)
        self._state = ServerSessionState.IN_CALL

    def mark_listening_again(self) -> None:
        """IN_CALL -> LISTENING when an inbound dispatch completes."""
        self._require_state(ServerSessionState.IN_CALL)
        self._state = ServerSessionState.LISTENING

    # Inbound TLV parsing reuses session.py's bounds-checked walker (T-05-S02);
    # Wave 2 (server core) consumes this to deserialize inbound call params.
    _parse_inbound_tlv = staticmethod(Session._parse_tlv)
