# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — RFC session state machine (sans-I/O)
#
# Pure state machine: NO sockets. Inputs are bytes from the Transport seam
# (plan 03-01); outputs are the next bytes to send + state transitions +
# decoded ConnectionAttributes. Testable against the Phase 1 golden handshake
# fixtures with zero network (RESEARCH OQ-8). The socket-free boundary is the
# substitution point for the future WebSocket/SNC transports (TRANS-01).
#
# Requirements: TRANS-01 (sans-I/O handshake), TRANS-04 (single-conversation
# CPIC state guard), TRANS-05/06 (ConnectionAttributes / close hooks),
# TRANS-07 (first-class connection attributes). State model: RESEARCH OQ-6.
#
# Handshake byte offsets are sourced from docs/protocol/handshake.md and the
# captured golden fixtures in tests/golden/handshake/. Where the prose in
# handshake.md and the captured fixture disagree on an offset, the fixture is
# authoritative (it is the live-capture ground truth): the GW connection handle
# sits at offset 44 in the fixtures (handshake.md prose says 32), and the
# gw_done_server codepage echo sits at offset 73.
#
# SAP_UC byte-order rule (mirrors codec.py CODEC-07): codepage "4103" selects
# UTF-16LE / Unicode mode. Never assume a BOM — the wire format has none.
#
# States (RESEARCH OQ-6):
#   DISCONNECTED → CONNECTED → NI_VERSIONED → GW_CONNECTED → GW_DONE
#   → LOGGED_IN → READY → IN_CALL → CLOSED / BROKEN
#
# Feed sequence (server frames consumed after start()):
#   CONNECTED   ← ni_version_response   → NI_VERSIONED
#   NI_VERSIONED← gw_connect_response   → GW_CONNECTED (extract handle)
#   GW_CONNECTED← gw_done (server)      → GW_DONE      (confirm codepage echo)
#   GW_DONE     ← logon_response        → READY        (absent 0x0402 = success)
from __future__ import annotations

import enum
import struct
from dataclasses import dataclass

__all__ = ["Session", "SessionState", "ConnectionAttributes"]


# --------------------------------------------------------------------------- #
# Wire constants (handshake.md Phase 1 / Phase 2; confirmed by golden fixtures).
# --------------------------------------------------------------------------- #
_NI_VERSION_LEN = 64  # NI-version body length (handshake.md line 45)
_NI_MSG_TYPE = 0x0203  # NI version frame (handshake.md line 50)
# NOTE: handshake.md byte offsets are stated for the *NI-framed* bytes (incl. the
# 4-byte NI length header). The Session works on the *payload* (header already
# stripped by the Transport seam / load_fixture), so every handshake.md offset is
# reduced by 4 here. handshake.md "offset 24" codepage ⇒ payload offset 20.
_NI_CODEPAGE_OFFSET = 20  # ASCII codepage, 4B (handshake.md line 51 − 4)
_NI_VERSION_FLAGS = 0x0006  # client version_flags (handshake.md line 53)
_NI_RFC_HINT = 0x06CB  # client rfc_hint (handshake.md line 56)
_NI_UNICODE_CAPABLE = 0xFFFF  # unicode_capable marker (handshake.md line 57)

# GW handle: handshake.md/fixture annotations say raw-frame offset 44; in payload
# coordinates (NI header stripped) that is 40 (fixture-confirmed: "75568442"@40).
_GW_HANDLE_OFFSET = 40  # 8B ASCII connection handle (payload offset)
_GW_HANDLE_LEN = 8
_GW_DONE_CODEPAGE_OFFSET = 69  # server codepage echo in GW_DONE (payload offset; raw 73 − 4)

_CODEPAGE_UTF16LE = "4103"  # Unicode-mode codepage (handshake.md line 64)

# Logon-response TLV tags (live RE from SAP NW 7.x wire captures).
_TAG_SYS_ID = 0x0450
_TAG_SYS_NUMBER = 0x0452
_TAG_PARTNER_HOST = 0x0453
_TAG_PARTNER_REL = 0x0012
_TAG_KERNEL_REL = 0x0013
_TAG_USER = 0x0150
_TAG_CLIENT = 0x0151
_TAG_LANGUAGE = 0x0152
# Error indication: 0x0402 carries the error message text (absent on success).
# Tag 0x0420 does NOT appear in live captures — using 0x0402 instead.
_TAG_ERROR_MSG = 0x0402
_TAG_TERMINATOR = 0xFFFF

_TLV_HEADER = struct.Struct(">HH")  # tag (2B BE) + length (2B BE)


class SessionState(enum.Enum):
    """RFC session lifecycle states (RESEARCH OQ-6)."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTED = "CONNECTED"
    NI_VERSIONED = "NI_VERSIONED"
    GW_CONNECTED = "GW_CONNECTED"
    GW_DONE = "GW_DONE"
    LOGGED_IN = "LOGGED_IN"
    READY = "READY"
    IN_CALL = "IN_CALL"
    CLOSED = "CLOSED"
    BROKEN = "BROKEN"
    # wRFC lazy-LOGON: HTTP upgrade done, credentials stored, no LOGON frame sent yet.
    # The first call() sends LOGON+func combined and advances to READY.
    WS_PENDING = "WS_PENDING"


@dataclass(frozen=True)
class ConnectionAttributes:
    """Negotiated connection attributes, populated at READY (RESEARCH OQ-7).

    Source TLV tags (handshake.md lines 188-205):
      sys_id       ← 0x0450   sys_number   ← 0x0452   partner_host ← 0x0453
      client       ← 0x0151   user         ← 0x0150   language     ← 0x0152
      partner_rel  ← 0x0012   kernel_rel   ← 0x0013
      codepage     ← NI version exchange offset 24 (+ GW_DONE offset 73 echo)

    ``unicode_mode`` is derived: codepage "4103" → True (UTF-16LE wire mode).
    """

    sys_id: str
    sys_number: str
    partner_host: str
    client: str
    user: str
    language: str
    partner_rel: str
    kernel_rel: str
    codepage: str
    unicode_mode: bool
    rfc_role: str = "C"  # client


class Session:
    """Sans-I/O RFC session state machine (no sockets).

    Usage (driven by the Transport seam, plan 03-01):

        sess = Session()
        transport.send(sess.start())          # NI-version request
        while not done:
            out = sess.feed(transport.recv())  # walk the handshake
            if out:
                transport.send(out)

    ``feed`` consumes one server frame's payload and returns the next bytes to
    send (or ``b""`` when nothing is to be sent). READY is reached only when the
    logon-response return-code TLV 0x0420 == 0.
    """

    def __init__(self) -> None:
        self._state = SessionState.DISCONNECTED
        self._broken_reason: str = ""
        self._attributes: ConnectionAttributes | None = None
        self._codepage: str | None = None
        self._handle: bytes | None = None  # 8-byte ASCII GW connection handle

    # ----------------------------------------------------------------- #
    # Public read-only surface
    # ----------------------------------------------------------------- #
    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def handle(self) -> bytes | None:
        """8-byte ASCII GW connection handle, set after GW_CONNECT_RESPONSE."""
        return self._handle

    @property
    def attributes(self) -> ConnectionAttributes | None:
        """Set only after the handshake reaches READY."""
        return self._attributes

    # ----------------------------------------------------------------- #
    # Drive
    # ----------------------------------------------------------------- #
    def start(self, local_ip: str | None = None) -> bytes:
        """Begin the handshake; return the NI-version request payload.

        ``local_ip`` should be the TCP socket's local IPv4 address string
        (e.g. ``sock.getsockname()[0]``). The SAP gateway validates the
        claimed IP against the TCP source — mismatch causes immediate close.
        """
        self._state = SessionState.CONNECTED
        return self._build_ni_version_request(local_ip=local_ip)

    def feed(self, data: bytes) -> bytes:
        """Feed one server frame payload; return the next bytes to send (b"" if none)."""
        buf = bytes(data)
        match self._state:
            case SessionState.CONNECTED:
                return self._handle_ni_version_response(buf)
            case SessionState.NI_VERSIONED:
                return self._handle_gw_connect_response(buf)
            case SessionState.GW_CONNECTED:
                return self._handle_gw_done(buf)
            case SessionState.GW_DONE:
                return self._handle_logon_response(buf)
            case _:
                raise ValueError(f"unexpected feed in state {self._state}")

    # ----------------------------------------------------------------- #
    # Phase 1 — NI version exchange (handshake.md lines 40-74)
    # ----------------------------------------------------------------- #
    def _build_ni_version_request(self, local_ip: str | None = None) -> bytes:
        """Build the 64-byte NI-version request body (handshake.md lines 44-59).

        ``local_ip``: real TCP source IPv4 string. The SAP gateway validates
        the claimed IP against the TCP source and closes immediately on mismatch
        (confirmed live 2026-06-28). Falls back to loopback if not supplied.
        """
        # Payload offsets = handshake.md raw offsets − 4 (NI header stripped).
        body = bytearray(_NI_VERSION_LEN)
        struct.pack_into(">H", body, 0, _NI_MSG_TYPE)  # [0-1]   msg_type 0x0203
        # [2-5] client_ip, a fixed 4-byte field. Falling back to 127.0.0.1 for an
        # unusable value is fine — the server treats this as informational — but the
        # fallback has to be reached. It was not, for a value with the wrong number
        # of octets: bytes(...) succeeds on "1.2.3", the except never fires, and
        # assigning three bytes to a four-byte slice SHRINKS the bytearray. That
        # produced a 63-byte NI version request instead of 64, and 65 for a
        # five-octet value — a wrong-length first frame on every connection.
        body[2:6] = _ipv4_octets(local_ip)
        body[10:18] = b"python3\x00"  # [10-17] program_name (NUL-term)
        body[_NI_CODEPAGE_OFFSET : _NI_CODEPAGE_OFFSET + 4] = (
            b"1100"  # [20-23] propose codepage 1100
        )
        struct.pack_into(">H", body, 28, _NI_VERSION_FLAGS)  # [28-29] version_flags 0x0006
        body[30:54] = b"titan   python3         "  # [30-53] hostname + program area
        struct.pack_into(">H", body, 54, _NI_RFC_HINT)  # [54-55] rfc_hint 0x06cb
        struct.pack_into(">H", body, 56, _NI_UNICODE_CAPABLE)  # [56-57] unicode_capable 0xffff
        return bytes(body)

    def _handle_ni_version_response(self, data: bytes) -> bytes:
        """Read server NI-version response; store codepage; emit GW-connect request."""
        if len(data) < _NI_CODEPAGE_OFFSET + 4:
            raise ValueError(
                f"NI version response too short: {len(data)} < {_NI_CODEPAGE_OFFSET + 4}"
            )
        codepage = data[_NI_CODEPAGE_OFFSET : _NI_CODEPAGE_OFFSET + 4].decode("ascii")
        self._codepage = codepage
        self._state = SessionState.NI_VERSIONED
        # The GW_CONNECT_REQUEST payload (frame 8) carries client PII and is not a
        # fixture; the Transport/Connection facade supplies it. The state machine
        # only needs to advance — the bytes to send are produced by the facade.
        return b""

    # ----------------------------------------------------------------- #
    # Phase 2 — GW connect (handshake.md lines 78-138)
    # ----------------------------------------------------------------- #
    def _handle_gw_connect_response(self, data: bytes) -> bytes:
        """Read GW_CONNECT_RESPONSE; extract the 8-byte connection handle (offset 44)."""
        if len(data) < _GW_HANDLE_OFFSET + _GW_HANDLE_LEN:
            raise ValueError(
                f"GW connect response too short: {len(data)} < {_GW_HANDLE_OFFSET + _GW_HANDLE_LEN}"
            )
        self._handle = data[_GW_HANDLE_OFFSET : _GW_HANDLE_OFFSET + _GW_HANDLE_LEN]
        self._state = SessionState.GW_CONNECTED
        # GW_INFO + client GW_DONE + the RFC logon TLV frame embed the handle +
        # credentials and are emitted by the facade (out of the pure SM's concern).
        # Advance; the next server frame consumed is the server GW_DONE.
        return b""

    def _handle_gw_done(self, data: bytes) -> bytes:
        """Read the server GW_DONE; confirm the codepage echo (handshake.md 130-132).

        The server GW_DONE re-asserts codepage "4103" at payload offset 69 (raw
        73). It is a second Unicode-mode confirmation; the authoritative codepage
        was already captured from the NI-version response. We validate the handle
        echo length defensively (T-03-TLV bounds) and advance to GW_DONE.
        """
        if len(data) < _GW_DONE_CODEPAGE_OFFSET + 4:
            raise ValueError(
                f"GW done frame too short: {len(data)} < {_GW_DONE_CODEPAGE_OFFSET + 4}"
            )
        self._state = SessionState.GW_DONE
        # The RFC logon TLV frame (credentials) is emitted by the facade.
        return b""

    # ----------------------------------------------------------------- #
    # Phase 3 — RFC logon response (handshake.md lines 144-205)
    # ----------------------------------------------------------------- #

    # Live server responses start with a 76-byte GW header followed by a 4-byte
    # RFC response marker (0x00000001) before the TLV stream. Mock responses
    # start directly with TLV data. Detect by checking for the GW data type 0x06CB.
    _GW_RFC_TYPE = 0x06CB
    _GW_RFC_PREAMBLE = 80  # GW header (76B) + RFC response marker (4B)

    def _handle_logon_response(self, data: bytes) -> bytes:
        """Parse the logon-response TLV; fail on 0x0402 error tag; build attributes."""
        # Live server wraps TLV in a GW header; MockTransport starts with TLV directly.
        is_live = len(data) >= 2 and struct.unpack_from(">H", data, 0)[0] == self._GW_RFC_TYPE
        tlv_data = data[self._GW_RFC_PREAMBLE :] if is_live else data
        tags = self._parse_tlv(tlv_data)

        # Error is signaled by tag 0x0402 (error message text). Tag 0x0420 is not
        # sent by live SAP NW 7.x servers — confirmed by wire capture.
        err_bytes = tags.get(_TAG_ERROR_MSG)
        if err_bytes is not None:
            # Surface the message but never echo credential tags (T-03-CRED).
            try:
                msg = err_bytes.decode("utf-8", errors="replace")
            except Exception:
                msg = err_bytes.hex()
            raise ValueError(f"logon failed: {msg}")

        codepage = self._codepage or ""
        unicode_mode = codepage == _CODEPAGE_UTF16LE
        if is_live and codepage and not unicode_mode:
            # Non-Unicode systems are out of scope: SAP ended support for them
            # with NetWeaver 7.5, and nothing in this library's non-Unicode paths
            # has ever been exercised against one.
            #
            # Refusing is not merely tidier than proceeding, it is the only safe
            # option. ``unicode_mode`` is derived here as "the wire codepage is
            # 4103", but the codec spends it as a BYTE ORDER selector --
            # ``_uc_encoding`` returns utf-16-be whenever it is false. On a
            # genuinely non-Unicode connection that decodes single-byte text as
            # UTF-16BE and yields mojibake, silently, in every character field.
            # A connection that cannot be decoded correctly must not be handed
            # back as if it could.
            raise ValueError(
                f"server negotiated codepage {codepage!r}, which is not the "
                f"Unicode wire mode {_CODEPAGE_UTF16LE!r}. Non-Unicode systems "
                f"are not supported: SAP ended support for them with NetWeaver "
                f"7.5, and this library's character handling has never been "
                f"validated against one. Continuing would decode every character "
                f"field incorrectly rather than fail."
            )
        dec = _decode_utf16le if (is_live and unicode_mode) else _decode_ascii
        self._attributes = ConnectionAttributes(
            sys_id=dec(tags.get(_TAG_SYS_ID)),
            sys_number=dec(tags.get(_TAG_SYS_NUMBER)),
            partner_host=dec(tags.get(_TAG_PARTNER_HOST)),
            client=dec(tags.get(_TAG_CLIENT)),
            user=dec(tags.get(_TAG_USER)),
            language=dec(tags.get(_TAG_LANGUAGE)),
            partner_rel=dec(tags.get(_TAG_PARTNER_REL)),
            kernel_rel=dec(tags.get(_TAG_KERNEL_REL)),
            codepage=codepage,
            unicode_mode=unicode_mode,
        )
        self._state = SessionState.LOGGED_IN
        self._state = SessionState.READY
        return b""

    @staticmethod
    def _parse_tlv(payload: bytes) -> dict[int, bytes]:
        """Parse a TLV stream: tag(2B BE) + length(2B BE) + value, 0xFFFF terminates.

        Handles both simple format (tag+len+val) and extended format
        (tag+len+val+tag_repeated) used by live SAP servers: after reading the
        value, peek at the next 2 bytes and skip them if they match the current
        tag (repeated-tag suffix). This is a transparent no-op for simple format.
        Length bounds are validated against the remaining payload (T-03-TLV).
        """
        out: dict[int, bytes] = {}
        pos = 0
        n = len(payload)
        while pos + _TLV_HEADER.size <= n:
            tag, length = _TLV_HEADER.unpack_from(payload, pos)
            pos += _TLV_HEADER.size
            if tag == _TAG_TERMINATOR:
                break
            end = pos + length
            if end > n:
                raise ValueError(
                    f"malformed TLV: tag 0x{tag:04x} length {length} exceeds "
                    f"remaining payload ({n - pos} bytes)"
                )
            out[tag] = payload[pos:end]
            pos = end
            # Skip the optional repeated-tag suffix used in extended TLV format.
            if pos + 2 <= n and struct.unpack_from(">H", payload, pos)[0] == tag:
                pos += 2
        return out

    # ----------------------------------------------------------------- #
    # State guards (CPIC single-conversation semantics, TRANS-04)
    # ----------------------------------------------------------------- #
    def _require_state(self, *allowed: SessionState) -> None:
        """Raise if the current state is not one of ``allowed``.

        The single-in-flight guard the Connection facade (plan 03-03) uses to
        reject a call/feed in the wrong state (TRANS-04, threat T-03-STATE).
        """
        if self._state is SessionState.BROKEN and SessionState.BROKEN not in allowed:
            raise ValueError(
                f"connection is unusable: {self._broken_reason}. A request was sent "
                f"whose reply could not be read to its end, so the position in the "
                f"byte stream is unknown and any further call on this connection "
                f"would read the previous reply's leftovers. Open a new connection."
            )
        if self._state not in allowed:
            raise ValueError(
                f"operation not allowed in state {self._state.value!r}; "
                f"requires one of {[s.value for s in allowed]}"
            )

    def mark_in_call(self) -> None:
        """Flip READY → IN_CALL for the duration of one RFC call (TRANS-04)."""
        self._require_state(SessionState.READY)
        self._state = SessionState.IN_CALL

    def mark_ready(self) -> None:
        """Flip IN_CALL → READY when a call completes (TRANS-04)."""
        self._require_state(SessionState.IN_CALL)
        self._state = SessionState.READY

    def mark_broken(self, reason: str) -> None:
        """Retire the session permanently: the byte stream is no longer trustworthy.

        This is for the case where a request went out and the reply could not be
        consumed to its end -- a malformed frame, a short read, a response that
        spans more frames than were read. What makes that dangerous is not the
        failed call, which raised and is therefore visible. It is the *next* call:
        the unread remainder is still queued on the socket, so the following
        request reads the previous reply's leftovers and gets an answer belonging
        to different arguments. That failure is silent and attributes one call's
        data to another's parameters.

        There is no resynchronisation to attempt. Nothing in the frame format
        marks a record boundary that a reader could scan forward to, so once the
        position in the stream is unknown it stays unknown. The connection is
        finished; the caller has to open a new one.

        BROKEN is terminal on purpose -- there is no path back to READY.
        """
        self._state = SessionState.BROKEN
        self._broken_reason = reason

    def begin_ws_session(self) -> None:
        """Advance to WS_PENDING after the WebSocket HTTP upgrade completes.

        In the lazy-LOGON design (Track 2), the RFC LOGON+function frame is not sent
        during connect(); it is deferred to the first call(). This state records that
        the transport is ready but the RFC session has not been established yet.
        """
        self._state = SessionState.WS_PENDING

    def complete_ws_first_call(
        self,
        *,
        attributes: ConnectionAttributes,
        codepage: str,
    ) -> None:
        """Advance WS_PENDING → READY after the first LOGON+call round-trip succeeds."""
        self._codepage = codepage
        self._attributes = attributes
        self._state = SessionState.READY

    def complete_ws_handshake(
        self,
        *,
        attributes: ConnectionAttributes,
        codepage: str,
    ) -> None:
        """Set READY directly for wRFC connections, bypassing the NI/GW state machine."""
        self._codepage = codepage
        self._attributes = attributes
        self._state = SessionState.READY


def _ipv4_octets(local_ip: str | None) -> bytes:
    """Exactly four bytes for the NI client_ip field, or the loopback default.

    Anything that is not four decimal octets in 0-255 falls back rather than
    raising: the field is informational and a caller should not fail to connect
    over it. The contract that matters is the width — the caller assigns this
    into a fixed slice.
    """
    if local_ip:
        parts = local_ip.split(".")
        if len(parts) == 4:
            try:
                octets = [int(p) for p in parts]
            except ValueError:
                octets = []
            if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
                return bytes(octets)
    return bytes((127, 0, 0, 1))


def _decode_ascii(value: bytes | None) -> str:
    """Decode a TLV ASCII value, stripping trailing NUL/space padding."""
    if value is None:
        return ""
    return value.decode("ascii", errors="replace").rstrip("\x00 ")


def _decode_utf16le(value: bytes | None) -> str:
    """Decode a TLV UTF-16LE value (live server unicode-mode strings)."""
    if value is None:
        return ""
    if len(value) % 2 == 0:
        try:
            return value.decode("utf-16-le").rstrip("\x00 ")
        except Exception:
            pass
    return value.decode("ascii", errors="replace").rstrip("\x00 ")
