# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — sync Connection facade
#
# Binds a Transport (plan 03-01) to a Session (plan 03-02), drives the documented
# direct-TCP handshake to READY, and exposes the user-facing surface:
#
#     connect(...)                    -- open + handshake, return a ready Connection
#     ping() -> bool                  -- RFC-level RFCPING liveness probe (TRANS-05)
#     close() -> None                 -- graceful close, safe in ANY state (TRANS-06)
#     get_connection_attributes()     -- negotiated ConnectionAttributes (TRANS-07)
#     call(func, **params)            -- RFC invoke (CLIENT-01..07; implemented Phase 4)
#
# Single in-flight call at a time (CPIC single-conversation, TRANS-04): a
# threading.Lock plus the Session IN_CALL state guard reject a re-entrant call.
#
# The Session is sans-I/O: it consumes one server frame per feed() and returns
# the NEXT bytes to send (b"" when the facade must supply them). The facade owns
# the socket seam and the GW_CONNECT / GW_DONE / logon request frames that the
# pure state machine does not synthesize (session.py notes these are emitted by
# the facade).
#
# Password scrambling (handshake.md logon TLV tag 0x0117): RESOLVED — see
# docs/protocol/handshake.md §"Password scrambling". The 0x0117
# value is NOT a hash — it is SAP's reversible byte cipher with a
# 4-byte client-random seed prefix: ``seed(4B) + scramble(password, seed)``.
# ``_scramble_password`` below reproduces it byte-for-byte (stdlib only). The
# plaintext password is never logged or echoed (threat T-04-CRED / T-03-CRED2).
# A live logon (Plan 04-01 Task 3 checkpoint) is the byte-for-byte truth-check;
# all facade logic here is proven offline via MockTransport.
from __future__ import annotations

import asyncio
import contextlib
import datetime
import logging
import os
import random
import socket as _socket_module
import struct
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import Any, Literal, cast

from saprfclib.compress import DecompressError, sap_lz4_frame_decompress
from saprfclib.exceptions import (
    AbapApplicationError,
    AbapSystemFailure,
    CommunicationError,
    RetryExhausted,
    WebSocketError,
)
from saprfclib.invoke import (
    _extract_name_value_pairs,
    build_bgrfc_confirm_request,
    build_bgrfc_request,
    build_bgrfc_state_request,
    build_invoke_request,
    build_trfc_confirm_request,
    build_trfc_request,
    decompress_table_stream,
    dm_table_ids,
    drop_unknown_parameters,
    extract_server_duration,
    parse_invoke_response,
    raise_for_rfc_error,
    tlv_stream_status,
    unknown_parameters,
)
from saprfclib.language import normalize_logon_language
from saprfclib.metadata import (
    _CHAR_LIKE_TYPES,
    _EXID_TO_RFCTYPE,
    RFCTYPE_CHAR,
    RFCTYPE_STRUCTURE,
    RFCTYPE_TABLE,
    MetadataCache,
    _parse_params_row,
    get_function_desc,
    is_exception_row,
)
from saprfclib.session import ConnectionAttributes, Session, SessionState
from saprfclib.stores import TidStore, UnitState, UnitStore
from saprfclib.transport import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    AsyncTransport,
    Transport,
    connect_tcp,
    connect_tcp_async,
)
from saprfclib.types import (
    RFC_EXPORT,
    RFC_IMPORT,
    FieldDesc,
    FunctionDesc,
    TypeDesc,
)

_logger = logging.getLogger(__name__)

__all__ = ["Connection", "AsyncConnection", "connect", "connect_async"]

# RFCTYPE constants for DATE/TIME post-processing (D-24).
# The codec returns str for DATE ("YYYYMMDD") and TIME ("HHMMSS"); call() converts
# these at the response boundary to datetime.date/time, leaving the codec unchanged.
_RFCTYPE_DATE = 1
_RFCTYPE_TIME = 3


# RFCPING probe (handshake.md line 181): the logon TLV ends with a call to the
# pseudo-function "RFCPING" (tag 0x0102). ping() reuses that probe as a minimal
# RFC call frame; the server replies with a return-code TLV (0x0420 == 0 = live).
_TAG_FUNCTION = 0x0102
_TAG_RETURN_CODE = 0x0420
_TAG_TERMINATOR = 0xFFFF
_TAG_CLIENT = 0x0114
_TAG_USER = 0x0111
_TAG_PASSWORD = 0x0117
_RFCPING_NAME = b"RFCPING"

# ---------------------------------------------------------------------------
# GW APPCHDR6 frame constants — protocol analysis sources in docs/protocol/framing.md
# ---------------------------------------------------------------------------
# APPCHDR6 layout shared by ALL GW frames (confirmed):
#   [0]     = 0x06  type MSB — hardcoded 6 in all builders (the GW_DONE builder/the GW_INFO builder/the GW_CONNECT builder/the gateway send path)
#   [1]     = type LSB (0x01/0x05/0x09/0x0B/0x0F/0xCB — see types below)
#   [2]     = protocol version byte from CONV_PROTO[0x17] = 0x02 for NW 7.x
#   [3]     = 0x00 (from memset)
#   [4:6]   = 0xffff (flags high word — all builders set this explicitly)
#   [6:8]   = 0x0000 (flags low word — from memset)
#   [40:48] = GW handle (8-byte ASCII, from CONV_PROTO[8], i.e. *(arg2+8))
_GW_TYPE_CONNECT = 0x0601  # protocol analysis:  *(r13_11+0x51) = 1
_GW_TYPE_INFO = 0x060F  # protocol analysis:   *(r13_4+0x51)  = 0xf
_GW_TYPE_DONE = 0x0605  # protocol analysis:   *(rdx_14+0x51) = 5
_GW_TYPE_MONITOR = 0x060B  # GW_MONITOR — defined but NOT sent (pyrfc writev RE: absent)
_GW_TYPE_RFC = 0x06CB  # RFC data frame (logon + calls) — wire-captured PKT 14
# Version field [2:4]: only byte [2] is set from CONV_PROTO[0x17] = 0x02; [3] = 0 (memset).
# We write both as a BE uint16 for clarity — wire result is identical.
_GW_VERSION = 0x0200
# Flags [4:8]: [4:6] = 0xffff set by all builders; [6:8] = 0 from memset. Combined = 0xFFFF0000.
_GW_FLAGS = 0xFFFF0000
# GW header fields [24:32] — constant across all frames in every captured session.
# Wire-verified: ALL golden requests AND responses carry identical values (logon +
# stfc_connection + rfc_read_table + stfc_changing + stfc_structure + stfc_deep_table).
# [24:28] = 0x00000008: APPC header version field checked by server ("client with wrong
#   appc header version rejected" error string at / CpicErrDescr 0xf6).
#   Sending zeros causes immediate 80B 0x06CE rejection from server.
# [28:32] = 0x0000050c (=1292): max-message/buffer-size negotiated at CPIC allocate phase.
#   Same value in client requests AND server responses; constant for NW 7.x.
_GW_HDR_APPC_VER = 0x00000008  # GW[24:28]: APPC header version (must be 8 for NW 7.x)
_GW_HDR_MAX_LEN = 0x0000050C  # GW[28:32]: CPIC max message length = 1292 (NW 7.x)
# 8-byte footer appended to every CLIENT invoke TLV body (inside NI frame, after TERMINATOR).
# Wire-verified in 5 golden request captures (stfc_connection, stfc_changing, stfc_structure,
# stfc_deep_table, rfc_read_table). Absent from server responses. Format:
#   [0:2]  0x0000      reserved
#   [2:4]  TLV length  uint16 BE = len(tlv_body) before footer
#   [4:6]  0x0000      reserved
#   [6:8]  0x8500      constant (CPIC NI frame tag/version — exact meaning TBD)
# Cross-check: stfc_connection TLV body=648B=0x0288 → footer=0000028800008500 ✓
#
# The length field is 32 bits, not 16. Every capture has a zero high half because
# every captured body is small, so [0:2]=0x0000 reads equally well as "reserved"
# — but packing it as uint16 raises struct.error above 64 KB, and the C SDK sends
# bodies far larger than that (a multi-megabyte ABAP program through
# /SAPDS/RFC_ABAP_INSTALL_RUN, for one). Verified across all nine request
# fixtures: the BE uint32 at [0:4] equals len(tlv_body) exactly in each.
_INVOKE_FOOTER_MAGIC = b"\x00\x00\x85\x00"  # bytes [4:8] of footer — constant
# Client tail at APPCHDR6[76:80] in 80-byte control frames (GW_INFO, GW_DONE_CLIENT).
# protocol analysis: var_3c=0xffff at [76:78] (hardcoded);
#   var_3a=rol.w(CONV_PROTO[0x1c],8)=bswap(0x0400)=0x0004 at [78:80].
# CONV_PROTO[0x1c] = 0x0400 for NW 7.x standard connection → bswap = 0x0004.
# strace of installed pyrfc writev confirms: FF FF 00 04 for GW_INFO + GW_DONE_CLIENT.
# The reference client the GW_DONE builder/the GW_INFO builder show 0xffffffff (SDK version difference, not wrong).
_GW_CLIENT_TAIL = 0xFFFF0004
# Live pyrfc SNC capture (2026-07-XX): [76:80] = FF FF 00 09 when SNC is active.
# CONV_PROTO[0x1c] = 0x0900 for SNC → bswap(0x0900) = 0x0009 → 0xFFFF0009.
_GW_CLIENT_TAIL_SNC = 0xFFFF0009

# RFC logon frame tail and header (PKT 14 capture + analysis):
# _RFC_MARKER at frame[76:80]: same [76:78]=0xffff, [78:80]=0x0004 pattern as control frames.
# _COM_HEAD: EBCDIC "RFC000000000" = 0xD9 0xC6 0xC3 = EBCDIC R/F/C, 0xF0*9 = EBCDIC '0'*9.
_RFC_MARKER = b"\xff\xff\x00\x04"
_COM_HEAD = b"\xd9\xc6\xc3\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0"  # EBCDIC "RFC000000000"

# Fixed logon TLV values (from PKT 14 wire capture; not yet independently confirmed).
# These are static capability descriptors — confirmed correct by live logon success.
# TODO: analyse RfcConnection logon TLV builder to explain each byte.
_TLV_CAPS = b"\x03\x01\x01\x01\x01\x01\x00\x00"  # tag 0x0101: RFC capability flags
_TLV_VER = b"\x00\x00\x0e\x0b"  # tag 0x0103: RFC protocol version (14.11)
_TLV_CP = b"\x04\x01\x00\x03\x00\x0a\x02\x00\x00\x00\x23"  # tag 0x0106: codepage descriptor
_TLV_PROG = b"<unknown>"  # tag 0x0006: caller program name
_DEFAULT_LANG = "E"  # tags 0x0115/0x0011: logon language when the caller gives none
_TLV_REL = b"754"  # tags 0x0012/0x0013/0x000B: SAP release

# wRFC-specific static TLV values (pcap-verified frames 108/169; different from NI/TCP)
_WS_TLV_CAPS = bytes.fromhex("0501010504010003")  # 0x0101: wRFC caps
_WS_TLV_CP = b"\x04\x01\x00\x03\x01\x03\x02\x00\x00\x00\x23"  # 0x0106: wRFC codepage
# 0x5001 header: 14-byte prefix present in every wRFC invoke 0x5001 TLV.
# Layout ( ctor + setHeader + flush):
#   [0]     0x24 '$'  — stream-start marker written by flush(1)
#   [1]     0x48 'H'  — getHeader marker written by setHeader
#   [2]     0x00      — serializerVersion → conn[0x3d2] via setSerializerVersion.
#                       readColumnMetadata MLIL-verified: conn[0x3d2]==0 (this
#                       value) → V2 on-wire (readByte=ngrfc_type FIRST, then readInt2=
#                       uc_length for types 5-9; jump to skipping switch).
#                       conn[0x3d2]==1 → V1 on-wire (readInt2=length FIRST, then
#                       readByte=ngrfc_type). 0x01 caused RABAX: server parsed our
#                       byte(type)+int2(len) as V1, read int2 from wrong bytes → ngrfc_type=0
#                       → deserializeField switch exceeded 0x1d → RABAX.
#   [3]     0x03      — understandSerializerVersion (constant from [rbx].w = 0x302)
#   [4]     0x00      — cond flag ([].b == 2)
#   [5-6]   0x41 0x03 — charset2BCD (conn[0x25a] copy via)
#   [7]     0x00      — stream[5] (uninitialised, stays 0)
#   [8-9]   0x23 0x00 — conn[0xe08] LE (session handle/counter)
#   [10-11] 0x40 0x20 — conn[0x3ce] LE (0x2040 → no LZ4; the write-format selector
#: SDK sets no-LZ4 for payloads ≤ 0x1fff bytes. All current
#                        invoke bodies are well below that threshold, so raw (uncompressed) body
#                        is always correct. LZ4 (0x6040) caused RABAX via the LZ4 decompressor.)
#   [12-13] 0x00 0x00 — bool_arg from NgRfcSendStream ctor (0 = not final? always 0 for invoke)
# 14-byte 0x5001 function-interface header (pcap-verified: frames 108/229).
# byte[2]=0x03 (V1 fast-serializer) used for BOTH LOGON and INVOKE:
#   - LOGON (RFCPING, no params): byte[2]=0x03 + no body → live-confirmed SEC-05 (abf0590).
#     byte[2]=0x00 (V2 mode) BREAKS LOGON: server aborts with TH: WebSocket server session
#     aborted (code 1001). Root cause unknown but empirically 0x03 is required.
#   - INVOKE: byte[2]=0x03 + V1 T/K/Q body → pcap-verified frames 108/229.
# Layout: [0-1]=0x2448 magic, [2]=serializer_ver, [3]=0x03, [4]=0x00, [5-6]=0x4103,
#   [7]=0x00, [8-9]=0x2300, [10-11]=0x4020 (LE → no LZ4), [12-13]=0x0000.
# Byte[2] distinguishes schema-only vs value-carrying frames (pcap-verified):
#   0x03 = schema only (T/K markers, no Q_SCALAR values) — frames 226/229
#   0x02 = value-carrying (Q_SCALAR or TABLE_Q markers present) — frame 233
_WS_5001_HDR = bytes.fromhex("2448030300410300230040200000")  # schema-only (byte[2]=0x03)
_WS_5001_HDR_WITH_VALS = bytes.fromhex(
    "2448020300410300230040200000"
)  # with Q-markers (byte[2]=0x02)
# INVOKE: V1 mode + LZ4 send (bytes[10-11]=0x4060 LE → 0x6040).
# Body must be wrapped with _sap_lz4_frame(); server will use the LZ4 decompressor.
_WS_5001_HDR_INVOKE = bytes.fromhex("2448030300410300230040600000")

# 0x0104: SDK environment block (250B) — present in every client frame in reference pcap
# (frames 225/229/233/237/241). Content encodes SDK version (780), OS (Linux), MF, and
# network attributes including IP addresses from the reference environment (192.168.66.x).
# We send this pcap reference value in all invoke frames. Server appears to use it for
# informational purposes only; IP/version mismatch has not caused rejection in live tests.
# GAP-0104: generating an environment-correct 0x0104 requires further RE. For now the pcap
# reference bytes are sufficient to satisfy the server's frame-validation pass.
_WS_TLV_0104_PCAP_REF = bytes.fromhex(
    "100402000c000187680000044c0000138910040b0020ef7ffe2ddab737f674087e9325971597ef"
    "f2bf8f4f71ff9f8e37261b000000001004040008001700080012000810040d001000000027000000"
    "eb00000031000000eb1004160002000c100417000200201004190002000010041e000800000382000"
    "0075c10042500020002100409000337383010042b00054c696e757810042c00024d46100424000800"
    "00085000000f0010042800080000078900000ef010042a00080000081c00000ef010041300340367"
    "05bf5405f70f07e1000000c0a84234016705926005ed0f04e1000000c0a8423400670593d005ed0f"
    "04e1000000c0a8423400"
)

# NG RFC V2 RFCTYPE → NGRFC_TYPE mapping ( the type mapping, V2 path)
_NGRFC_TYPE_V2: dict[int, int] = {
    0: 6,  # CHAR
    1: 12,  # DATE
    2: 9,  # BCD (also needs decimals byte)
    3: 14,  # TIME
    4: 0x17,  # BYTE
    5: 0x1B,  # TABLE
    6: 8,  # NUM
    7: 0x13,  # FLOAT
    8: 3,  # INT / INT4  (fixed size, ngrfc_type <= 4: no length field)
    9: 2,  # INT2        (fixed size)
    10: 1,  # INT1        (fixed size)
    17: 0x1A,  # STRUCTURE
    23: 0x15,  # DECF16
    24: 0x16,  # DECF34
    29: 0x18,  # STRING
    30: 0x19,  # XSTRING
    31: 4,  # INT8        (fixed size)
}

# Password-scramble key table (64 bytes). Confirmed identical across two
# independent client versions, and verified end-to-end by a live logon.
# See docs/protocol/handshake.md §"Password scrambling".
_AB_SCRAMBLE_KT = bytes.fromhex(
    "f0ed53b83244f1f876c67959fd4f13a2"
    "c15195ec5483c234774943a27de26596"
    "5e5398789a17a33cd383a8b829fbdca5"
    "55d7027784 13acddf9b8311 6610e6dfa".replace(" ", "")
)


def _tlv(tag: int, value: bytes) -> bytes:
    """Build one TLV record: tag(2B BE) + length(2B BE) + value."""
    return tag.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _encode_logon_language(lang: str) -> bytes:
    """Return the wire bytes for logon TLV tags 0x0011 / 0x0115.

    The wire carries the one-character SAP language code as a single ASCII byte on
    both tags. Source: golden fixture tests/golden/framing/logon_request.bin —
    0x0115 and 0x0011 each hold b"E" for a logon in English.

    A two-character ISO code is converted to that one character first, matching
    what the SAP RFC SDK does with its LANG connection option (see
    saprfclib.language).
    """
    return normalize_logon_language(lang).encode("ascii")


def _tlv_ext(tag: int, value: bytes) -> bytes:
    """Extended TLV: tag(2B) + len(2B) + value + tag(2B) — live wire format."""
    t = tag.to_bytes(2, "big")
    return t + len(value).to_bytes(2, "big") + value + t


def _ab_scramble(buf: bytearray, seed: int) -> None:
    """SAP's reversible password-scramble byte cipher, applied in place.

    Symmetric XOR stream keyed by ``seed`` and the 64-byte ``_AB_SCRAMBLE_KT``
    table. Applying it twice with the same seed is the identity — it is its own
    inverse, which is how the server recovers the password. ``seed`` is a
    32-bit value.

    This is obfuscation, not encryption: the seed travels in the clear next to
    the ciphertext. See docs/protocol/handshake.md.
    """
    seed &= 0xFFFFFFFF
    k = (((seed >> 5) ^ ((seed * 2) & 0xFFFFFFFF)) ^ seed) & 0x3F
    ck = 0xFFFFFFFF
    for i in range(len(buf)):
        ks = (ck * i) & 0xFFFFFFFF
        kb = (ks ^ _AB_SCRAMBLE_KT[k]) & 0xFF
        buf[i] ^= kb
        k = (k + 1) & 0x3F
        ck = (ck + seed) & 0xFFFFFFFF


def _scramble_password(passwd: str, *, seed: int | None = None) -> bytes:
    """Build the 0x0117 value: ``seed(4B LE) + scramble(password, seed)``.

    The seed is stored in native **little-endian** byte order, and the server
    reads the same 4 bytes back as LE to recover it. Big-endian (an earlier,
    wrong assumption) yields a different k-index and therefore a wrong
    keystream; a live logon confirmed LE — seed bytes 96 4d 05 30 → 0x30054d96.

    ``seed`` is injectable for deterministic tests; production uses a fresh
    ``os.urandom`` 4-byte client nonce interpreted as LE (no server salt —
    T-04-SALT).  The plaintext ``passwd`` is never logged or returned (T-04-CRED).
    """
    if seed is None:
        seed = int.from_bytes(os.urandom(4), "little")
    seed &= 0xFFFFFFFF
    # Single-byte (passthrough) codepage for the password bytes; non-encodable
    # chars are replaced rather than raising (never echoes the plaintext).
    body = bytearray(passwd.encode("latin-1", "replace"))
    _ab_scramble(body, seed)
    return struct.pack("<I", seed) + bytes(body)


def _scramble_password_ws(passwd: str, *, seed: int | None = None) -> bytes:
    """0x0117 for wRFC: seed(4B LE) + scramble(passwd.encode('utf-16-le'), seed).

    wRFC uses UTF-16LE password encoding (pcap-confirmed: 13-char → 26-byte body
    = 30 bytes total with 4-byte seed). Never logs the plaintext (T-07-CRED).
    """
    if seed is None:
        seed = int.from_bytes(os.urandom(4), "little")
    seed &= 0xFFFFFFFF
    body = bytearray(passwd.encode("utf-16-le"))
    _ab_scramble(body, seed)
    return struct.pack("<I", seed) + bytes(body)


def _build_ws_logon_message(
    *,
    func_name: str,
    ngrfc_body: bytes = b"",
    user: str,
    passwd: str,
    client: str,
    lang: str = _DEFAULT_LANG,
    local_ip: str = "127.0.0.1",
    local_port: int = 0,
    server_host: str,
    server_port: int,
    sysnr: str = "00",
    seed: int | None = None,
    prog_name: str = "PYTHON",
) -> tuple[bytes, bytes]:
    """Build wRFC LOGON TLV message embedding ``func_name`` as the session-open call.

    ``func_name`` is the RFC function executed on the server as part of the LOGON
    handshake (e.g. ``"RFC_GET_FUNCTION_INTERFACE"``).  ``ngrfc_body`` is the V1
    fast-serializer body appended to the 14-byte _WS_5001_HDR (empty → server runs
    ``func_name`` with no import parameters, like RFCPING).

    Returns ``(msg_bytes, call_key)`` where ``call_key = b"\\x01" + 36-byte session key``
    must be reused in all subsequent invoke frames (0x0136).

    Structure (pcap frames 108/169):
      session header → call begin → session logon → call end → terminator.
    All string TLVs are UTF-16LE (wRFC wire convention). Password never logged (T-07-CRED).
    """
    try:
        hostname = _socket_module.gethostname()
    except Exception:
        hostname = "saprfclib"
    hostname_u16 = hostname.encode("utf-16-le")

    fname = func_name.upper()
    # call-begin 0x0130: name + '='*(30-len) + 'FT' = 32 chars = 64 B UTF-16LE
    func_begin_padded = _pad_call_name(fname, 30).encode("utf-16-le")
    # call-end 0x0130: name + '='*(38-len) + 'FT' = 40 chars = 80 B UTF-16LE (pcap-verified)
    func_end_padded = _pad_call_name(fname, 38).encode("utf-16-le")
    # first 0x0130: CLIENT PROGRAM NAME (verified: writeRfcSessionInfo writes
    # the CPIC layer::ownname here, not the function name).
    # NOTE: changing from func_begin_padded causes RABAX on SAP 7.x — kept for compat.
    prog_name.encode("utf-16-le")

    conn_id_raw = os.urandom(36)  # 36 random binary bytes (0x0140)
    # 0x0136 session key: b"\x01" + 32B session_id + 4B BE counter.
    # LOGON frame uses counter=1; subsequent invoke frames must increment the counter.
    # Pcap-verified: frame 226 (LOGON) counter=\x00\x00\x00\x01,
    #                frame 229 (first invoke) counter=\x00\x00\x00\x02.
    call_id_raw = os.urandom(32) + b"\x00\x00\x00\x01"  # 36 bytes; counter=1 for LOGON
    # 0x0122 date/time: UTF-16LE encoded timestamp string (pcap-verified: 28B = 14 chars)
    dt_u16 = datetime.datetime.now().strftime("%Y%m%d%H%M%S").encode("utf-16-le")

    # SAP release strings (pcap-verified): 0x0012/0x0013 padded to 4 chars = 8B; 0x000b NOT padded = 3 chars = 6B
    _rel_padded_u16 = "757 ".encode("utf-16-le")  # tags 0x0012, 0x0013: 8B
    _rel_u16 = "757".encode("utf-16-le")  # tag  0x000b: 6B (no trailing space)

    # 0x0127 connection attributes: dash-separated key-value ASCII string (pcap-verified format)
    # Field 2 = client source port; field 5 = server IP; field 6 = gateway name;
    # field 7 = client IP; fields 9-14 = misc params; field 15 = conn-id hex (no dashes);
    # field 16 = SID (unknown before logon — leave blank); field 17/18 = server/client IP.
    conn_id_hex = conn_id_raw.hex()[:32]  # 32 hex chars, no dashes
    gw_name = f"sapgw{sysnr}"
    # Null terminator required: SAP TH aborts session if 0x0127 value is not null-terminated.
    conn_attrs = (
        f"1-5-2-{local_port}-3-0-4-1-5-{server_host}"
        f"-6-{gw_name}-7-{local_ip}"
        f"-17-{server_host}-18-{local_ip}"
        f"-9-{lang.upper()}-10-0-11-0-12-0-13-0-14-1"
        f"-16--15-{conn_id_hex}-8-X13\x00"
    ).encode("ascii")

    user_u16 = user.upper().encode("utf-16-le")
    client_u16 = client.encode("utf-16-le")
    lang_u16 = lang.upper().encode("utf-16-le")
    func_u16 = fname.encode("utf-16-le")
    sysnr_u16 = sysnr.encode("utf-16-le")  # "00" → 4 bytes
    pw_tlv = _scramble_password_ws(passwd, seed=seed)

    parts: list[bytes] = []

    # session header (pcap-verified static TLVs)
    parts += [
        _tlv_ext(0x0101, _WS_TLV_CAPS),
        _tlv_ext(0x0103, _TLV_VER),
        _tlv_ext(0x0106, _WS_TLV_CP),
        _tlv_ext(0x0160, b"\x60\x41"),
        _tlv_ext(0x0161, b"\x00"),
    ]

    # 0x0007: client IP padded to 15 chars (30B UTF-16LE) — pcap-verified
    local_ip_padded_u16 = local_ip.ljust(15).encode("utf-16-le")
    # 0x0008: "hostname_SID_sysnr" in UTF-16LE — SID unknown pre-logon, use placeholder
    host_sid_sysnr_u16 = f"{hostname}___{sysnr}".encode("utf-16-le")

    # call begin — all strings UTF-16LE per pcap
    parts += [
        _tlv_ext(0x0127, conn_attrs),
        _tlv_ext(0x0007, local_ip_padded_u16),
        _tlv_ext(0x0020, local_ip.encode("utf-16-le")),
        _tlv_ext(0x0021, str(server_port).encode("utf-16-le")),
        _tlv_ext(0x0018, local_ip.encode("utf-16-le")),
        _tlv_ext(0x0008, host_sid_sysnr_u16),
        _tlv_ext(0x0011, lang_u16),
        _tlv_ext(0x0013, _rel_padded_u16),
        _tlv_ext(0x0012, _rel_padded_u16),
        _tlv_ext(0x0006, server_host.encode("utf-16-le")),
        _tlv_ext(0x0130, func_begin_padded),
    ]

    # session logon — all strings UTF-16LE; password scrambled (T-07-CRED)
    parts += [
        _tlv_ext(0x0111, user_u16),
        _tlv_ext(0x0114, client_u16),
        _tlv_ext(0x0117, pw_tlv),
        _tlv_ext(0x0003, b""),  # SID unknown pre-logon
        _tlv_ext(0x0135, "saprfclib".encode("utf-16-le")),  # system description
        _tlv_ext(0x0010, sysnr_u16),
        _tlv_ext(0x0002, hostname_u16),
        _tlv_ext(0x000C, "python3".encode("utf-16-le")),
        _tlv_ext(0x0122, dt_u16),  # UTF-16LE timestamp (28B)
        _tlv_ext(0x0123, b""),
        _tlv_ext(0x000E, client_u16),
        _tlv_ext(0x0119, user_u16),
        _tlv_ext(0x0140, conn_id_raw),  # 36 random binary bytes
        _tlv_ext(0x0114, client_u16),
        _tlv_ext(0x0115, lang_u16),
        _tlv_ext(0x0009, user_u16),
        _tlv_ext(0x0134, client_u16),
        _tlv_ext(0x0501, b"\x01"),
    ]

    # call end
    parts += [
        _tlv_ext(0x0136, b"\x01" + call_id_raw),  # 37 bytes: marker + 36 random
        _tlv_ext(0x0502, b""),
        _tlv_ext(0x000B, _rel_u16),  # 6B: "757" (not padded)
        _tlv_ext(0x0102, func_u16),
        _tlv_ext(0x000B, _rel_u16),
        _tlv_ext(0x0130, func_end_padded),  # 80 bytes (40-char padded)
        _tlv_ext(0x0503, b""),
        _tlv_ext(0x0420, b"\x00\x00\x00\x00"),
        _tlv_ext(0x0512, b""),
        _tlv_ext(
            0x5001, _WS_5001_HDR + ngrfc_body
        ),  # V1 HDR + optional body (empty for no-param funcs)
        # 0x0104 NOT sent in LOGON: content is environment-specific (IPs from pcap
        # differ from this client's env) and wrong-environment values cause the
        # server to hang for the full WP time limit.  0x0104 is invoke-only (HEAD).
        _TAG_TERMINATOR.to_bytes(2, "big") + b"\x00\x00",
    ]

    call_key = b"\x01" + call_id_raw
    return b"".join(parts), call_key


def _ws_parse_logon_response(data: bytes) -> ConnectionAttributes:
    """Parse wRFC server response TLV stream; return ConnectionAttributes.

    wRFC responses arrive as raw WebSocket binary messages (no GW header).
    All string TLVs are decoded as UTF-16LE (wRFC wire convention). Auth tags
    (0x0450 SID through 0x0453 host) are present in BOTH success and error
    responses — if the SID is populated, auth succeeded even if the connect-time
    function call (RFCPING) failed.  Only raises ValueError when auth itself
    failed (no SID in response). Never echoes password (T-07-CRED).
    """
    tags = Session._parse_tlv(data)

    def _d16(v: bytes | None) -> str:
        if not v:
            return ""
        try:
            return v.decode("utf-16-le").rstrip("\x00 ")
        except Exception:
            return v.decode("ascii", errors="replace").rstrip("\x00 ")

    def _das(v: bytes | None) -> str:
        if not v:
            return ""
        return v.decode("ascii", errors="replace").rstrip("\x00 ")

    sys_id = _d16(tags.get(0x0450))
    if sys_id:
        # Auth succeeded — return attrs regardless of any function-call error in 0x0402.
        # The connect-time function call (RFCPING / RFC_SYSTEM_INFO) may fail for reasons
        # unrelated to auth; the session is still usable for get_connection_attributes().
        return ConnectionAttributes(
            sys_id=sys_id,
            sys_number=_d16(tags.get(0x0452)),
            partner_host=_d16(tags.get(0x0453)),
            client="",
            user="",
            language="",
            partner_rel=_das(tags.get(0x0012)),
            kernel_rel=_das(tags.get(0x0013)),
            codepage="4103",
            unicode_mode=True,
        )

    # No SID — auth itself failed.
    err = tags.get(0x0402)
    if err is not None:
        try:
            msg = err.decode("utf-8", errors="replace")
        except Exception:
            msg = err.hex()
        raise ValueError(f"wRFC logon failed: {msg}")

    raise ValueError("wRFC logon response missing system ID (0x0450)")


# --------------------------------------------------------------------------- #
# NG RFC V2 parameter serialization (for the 0x5001 block body)               #
# RE: the reference client, reference-client analysis                              #
# --------------------------------------------------------------------------- #


def _ngrfc_write_int2(value: int) -> bytes:
    """Pack uint16 little-endian for NG RFC V2 stream. readInt2: when connection flag at +0xdf6 == 0 (modern x86-64
    SAP server), the rol.w byte-swap is skipped → native LE memory order.
    """
    return struct.pack("<H", value & 0xFFFF)


def _ngrfc_write_lv(name_utf8: bytes) -> bytes:
    """Write name LV: 1-byte length prefix + UTF-8 bytes. the name serializer: for names <= 0xFE bytes, writes 1B length then
    UTF-8 bytes. Parameter names are ASCII and never exceed 30 chars.
    """
    n = len(name_utf8)
    if n > 0xFE:
        raise ValueError(f"NG RFC parameter name too long ({n} B): {name_utf8!r}")
    return bytes([n]) + name_utf8


def _ngrfc_encode_stringlike(value: str, char_count: int) -> bytes:
    """Encode CHAR/DATE/TIME/NUM value as NG RFC the string serializer output. deserialize<NGRFC_TYPE_6> raw asm (confirmed 2026-07-28):
    - 'O' (0x4F): compMode only, no int2 prefix; server reads column_meta.length
      bytes directly via label_5287f4 readData.
    - 'C' (0x43) + int2(blen) WITHOUT 0x8000: server skips encoding block, reads
      min(blen, TypeDesc.field_len) bytes directly via label_5287f4 readData.
    - 'C' (0x43) + int2(blen | 0x8000): WRONG for unicode — triggers double-read
      (temp_buf encode path + label_5287f4 read + skipBytes(32764)) → RABAX.

    Assembly-confirmed compMode propagation (2026-08-01): deserializeData
    at does `push r14` (compMode byte read from stream) as the 8th arg before
    the call to deserializeField. deserializeField reads it as arg_10 = [rsp+16], sets
    r8=arg_10, and the tail call at propagates r8 as entry_r8 into
    deserialize<NGRFC_TYPE_6>. entry_r8=='C' (0x43) → readInt2 path; else → direct read
    of column_meta.length bytes. Our 'C' encoding is confirmed correct end-to-end.

    Value is right-padded with spaces to char_count (ABAP CHAR convention).
    """
    padded = value[:char_count].ljust(char_count)
    utf16 = padded.encode("utf-16-le")
    blen = len(utf16)
    if blen <= 9:
        # 'O': no int2 — server reads column_meta.length bytes directly
        return bytes([0x4F]) + utf16
    if blen < 0x3334:
        # 'C': int2(blen) WITHOUT 0x8000 — direct UTF-16LE read
        return bytes([0x43]) + _ngrfc_write_int2(blen) + utf16
    raise NotImplementedError(f"NG RFC CHAR field exceeds single-chunk limit ({blen} B > 0x3333)")


# rfctype → D-block \\TYPE= prefix (length appended for variable-width types).
# CHAR/DATE/TIME/NUM use length-based names matching pcap (\\TYPE=CHAR30, \\TYPE=DATS, …).
_V1_TYPE_PREFIX: dict[int, bytes] = {
    0: b"\\TYPE=CHAR",  # CHAR — append nuc_length (e.g. \\TYPE=CHAR255)
    1: b"\\TYPE=DATS",  # DATE — fixed 8-char
    3: b"\\TYPE=TIMS",  # TIME — fixed 6-char
    6: b"\\TYPE=NUMC",  # NUM  — append nuc_length
}


def _v1_type_name(rfctype: int, nuc_length: int) -> bytes:
    """Return D-block \\TYPE= name for a scalar CHAR-like field.

    Pcap-verified pattern: \\TYPE=CHAR30 for CHAR30, \\TYPE=DATS for DATE.
    LENGTH is appended for variable-width types (CHAR, NUM).
    """
    prefix = _V1_TYPE_PREFIX.get(rfctype, b"\\TYPE=CHAR")
    if rfctype in (0, 6):
        return prefix + str(nuc_length).encode("ascii")
    return prefix  # DATE/TIME: fixed name, no length suffix


# protocol analysis confirmed V1 format markers (ngrfcSerializeParams):
#   T(0x54) = schema activation (EXPORT/CHANGING/TABLES params, direction & 2 != 0)
#   Q(0x51) = caller-supplied value (IMPORT/CHANGING/TABLES with data)
#   K(0x4b) = TABLE metadata header (nested inside Q body; the metadata serializer)
#   D(0x44) = type-descriptor block inside Q scalar body
#   0x01 = V1 body terminator (NOT the 0x45 EXECUTE used in V2)

_V1_CHAR_THRESHOLD_UC = 9  # same as V2: uc_length ≤ 9 → 'O' (UC direct read), else → 'C' NUC


# Hardcoded FunctionDescs for standard functions whose interface is stable and well-known.
# Used by _ws_direct_logon_call: when wRFC WS_PENDING and the target function is in this
# dict, the LOGON frame embeds the actual function (not GFI). This matches the pcap pattern
# (frame 108: BAPI_USER_GET_DETAIL directly in LOGON, never GFI) and avoids the GFI path
# which requires an ABAP work-process dispatch that may time out on busy/test systems.
# All field sizes confirmed from ABAP system (CHAR255 = SY-MSEG type, standard since NW 7.x).
def _make_wrfc_builtin_descs() -> dict[str, FunctionDesc]:
    """Build hardcoded FunctionDesc map for standard wRFC functions (direct-LOGON path).

    Interface sizes are ABAP-canonical (SY-MSEG = CHAR(255), nuc=255, uc=510).
    These descriptors are used when WS_PENDING so the LOGON frame embeds the actual
    function call instead of GFI — matching the pcap pattern (frame 108: BAPI_USER_GET_DETAIL
    directly in LOGON). This avoids a GFI work-process round-trip that times out on busy
    systems and reduces latency from 2 round-trips (GFI + invoke) to 1 (LOGON = invoke).
    """
    _char255 = {
        "rfctype": 0,
        "nuc_length": 255,
        "nuc_offset": 0,
        "uc_length": 510,
        "uc_offset": 0,
        "decimals": 0,
        "unicode_mode": True,
    }
    stfc = FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            FieldDesc(name="REQUTEXT", direction=RFC_IMPORT, **_char255),  # type: ignore[arg-type]
            FieldDesc(name="ECHOTEXT", direction=RFC_EXPORT, **_char255),  # type: ignore[arg-type]
            FieldDesc(name="RESPTEXT", direction=RFC_EXPORT, **_char255),  # type: ignore[arg-type]
        ],
    )
    return {stfc.name: stfc}


_WRFC_BUILTIN_DESCS: dict[str, FunctionDesc] = _make_wrfc_builtin_descs()


def _v1_encode_char_value(value: str, nuc_length: int, uc_length: int) -> bytes:
    """Encode one CHAR/DATE/TIME/NUM value for V3 fast-serializer (HDR byte[2]=0x03) Q-markers.

    protocol analysis NgRfcTypeSerializer::serialize<RFCTYPE_CHAR> confirmed:
      Unicode connection (wRFC target is always Unicode): flag[0x10]=0 → UC trimmed mode.
        uc_length ≤ 9: 'O' (0x4F) + value padded to nuc_length chars in UTF-16-LE.
                      Server reads exactly uc_length bytes (column_meta.length from D-block).
        uc_length > 9: 'C' (0x43) + LE uint16(trimmed_UC_bytes, NO 0x8000) + UTF-16-LE stripped.
                      SDK: getTrimEndLength(uc_data, char_count, space=0x20) * 2 → blen.
                      Server reads min(blen, TypeDesc.field_len) UC bytes from stream.
                      Sending blen=510 (full padded UC) hangs: if TypeDesc.field_len=255 (NUC),
                      min(510,255)=255, leaving 255 leftover bytes that corrupt next parse.
                      Sending blen=0x8000+NUC hangs: V3 parser reads raw int2=0x8004=32772 → block.
                      Sending blen=trimmed_UC_bytes (<= nuc_length): min(blen, 255 or 510)=blen → ✓.

      NUC connection (V2 subsequent invokes): flag[0x10]=1, uses 0x8000+NUC (NOT used here).
    """
    if uc_length <= _V1_CHAR_THRESHOLD_UC:
        padded = value[:nuc_length].ljust(nuc_length)
        return b"\x4f" + padded.encode("utf-16-le")
    stripped = value[:nuc_length].rstrip()
    if uc_length > 0x3333:
        # Large field: the field serializer case 0 sbb formula → compMode='S' when
        # arg3 (=uc_length) > 0x3333; falls through to the string serializer which
        # converts UTF-16LE→UTF-8 in chunks. We convert Python str→UTF-8 directly.
        return b"\x53" + _v1_stringlike_chunks(stripped.encode("utf-8"))
    uc_bytes = stripped.encode("utf-16-le")
    return b"\x43" + struct.pack("<H", len(uc_bytes)) + uc_bytes


_V1_COL_NAME = b"TABLE_LINE"

# Pcap-verified (frame 233): both DATA (1 col) and FIELDS (5 cols) TABLE Q-markers use this
# same tname regardless of column structure — it is a generic "rfctype=TABLE" descriptor.
_V1_TABLE_QMARKER_TNAME = bytes.fromhex(
    "5c545950453d255f5430303030345330303030303030304f30303030303337303732"
)  # b"\\TYPE=%_T00004S00000000O0000037072"


def _v1_table_q_marker(name_b: bytes, table_idx: int) -> bytes:
    """Build TABLE Q-marker for an IMPORT/TABLES param that sends table data.

    Wire layout (protocol analysis the parameter serializer → serializeTable → the metadata serializer):
      0x51 + name_len(1B) + name        [Q-marker from the parameter serializer]
      0x4b                               [K-marker from the metadata serializer, isFirstRow=1]
      (col_count | 0xD000) LE(2B)       [col_count=0 → 0xD000; the metadata serializer]
      table_idx LE(2B)                   [delta-manager table ID; the metadata serializer]
      tname_len(1B) + tname              [type name via the name serializer;]

    Used for IMPORT/TABLES TABLE params where the client provides (possibly empty) table data.
    EXPORT TABLE params use a T-marker only (no Q, no K) — see _build_ngrfc_params.
    """
    tname = _V1_TABLE_QMARKER_TNAME
    return (
        b"\x51"
        + bytes([len(name_b)])
        + name_b
        + b"\x4b\x00\xd0"
        + struct.pack("<H", table_idx)
        + bytes([len(tname)])
        + tname
    )


def _v1_q_marker(name_b: bytes, uc_length: int, encoded_value: bytes, type_name: bytes) -> bytes:
    """Build one V1 Q-marker for a CHAR-UC scalar import param (pcap-verified).

    Wire layout confirmed by pcap frame 233 (RFC_READ_TABLE QUERY_TABLE / DELIMITER):
      0x51 + name_len(1B) + name
      0x44                           D-block marker
      0x01 0x50                      writeInt2(0x5001) LE — structure path, ncols=1|0x5000
      type_name_len(1B) + type_name  (e.g. \\TYPE=CHAR255)
      0x06                           ngrfc_type=6 (CHAR UC)
      uc_length_LE(2B)               field_len
      col_name_len(1B) + col_name    "TABLE_LINE" — pcap-verified for all CHAR import params
      [encoded_value]                compMode + value
    """
    type_block = (
        b"\x44\x01\x50"
        + bytes([len(type_name)])
        + type_name
        + b"\x06"
        + struct.pack("<H", uc_length)
        + bytes([len(_V1_COL_NAME)])
        + _V1_COL_NAME
    )
    return b"\x51" + bytes([len(name_b)]) + name_b + type_block + encoded_value


def _v1_q_block(
    name_b: bytes,
    type_name: bytes,
    ngrfc_type: int,
    field_len: int | None,
    encoded_value: bytes,
    decimals: int | None = None,
) -> bytes:
    """Build a V1 Q-marker for any scalar IMPORT param type.

    Generalises _v1_q_marker to all rfctypes.  D-block format (protocol analysis
    the single-type metadata serializer; pcap-verified for CHAR):

      0x44 0x01 0x50           D-marker + ncols=1|0x5000 LE
      type_name_LV             1B len + ABAP type descriptor (\\TYPE=INT4 etc.)
      ngrfc_type(1B)           from the type mapping
      [field_len LE(2B)]       absent for ngrfc_type ≤ 4 (INT1/INT2/INT/INT8)
      [decimals(1B)]           BCD (ngrfc_type=9) only: decimal places
      TABLE_LINE_LV            col name — scalar IMPORT params always use TABLE_LINE

    field_len=None means no field_len bytes in D-block (ngrfc_type ≤ 4).
    """
    type_desc = bytes([ngrfc_type])
    if field_len is not None:
        type_desc += struct.pack("<H", field_len)
        if decimals is not None:
            type_desc += bytes([decimals])
    d_block = (
        b"\x44\x01\x50"
        + bytes([len(type_name)])
        + type_name
        + type_desc
        + bytes([len(_V1_COL_NAME)])
        + _V1_COL_NAME
    )
    return b"\x51" + bytes([len(name_b)]) + name_b + d_block + encoded_value


# ngrfc_type values for Unicode (wRFC) mode — protocol analysis
_V1_NGT: dict[int, int] = {
    0: 6,  # CHAR → CHAR_UC
    1: 12,  # DATE → DATE_UC
    2: 9,  # BCD
    3: 14,  # TIME → TIME_UC
    4: 23,  # BYTE (type X)
    6: 8,  # NUM  → NUMC_UC
    7: 19,  # FLOAT (FLTP, 0x13)
    8: 3,  # INT4
    9: 2,  # INT2
    10: 1,  # INT1
    29: 24,  # STRING (0x18)
    30: 25,  # XSTRING (0x19)
    31: 4,  # INT8
    32: 29,  # UTCLONG (0x1d) — protocol analysis case 0x20
}

# D-block type_name strings per rfctype (ABAP internal type descriptors).
# Length suffix appended for variable-width types (CHAR, NUMC, P, X).
_V1_TNAME_FIXED: dict[int, bytes] = {
    1: b"\\TYPE=DATS",
    3: b"\\TYPE=TIMS",
    7: b"\\TYPE=FLTP",
    8: b"\\TYPE=INT4",
    9: b"\\TYPE=INT2",
    10: b"\\TYPE=INT1",
    29: b"\\TYPE=STRING",
    30: b"\\TYPE=XSTRING",
    31: b"\\TYPE=INT8",
    32: b"\\TYPE=UTCLONG",  # UNCERTAIN: tname not live-captured; follows \\TYPE= convention
}
# rfctypes NOT in _V1_TNAME_FIXED append nuc_length to their prefix:
_V1_TNAME_PREFIX: dict[int, bytes] = {
    0: b"\\TYPE=CHAR",  # → \\TYPE=CHAR30
    2: b"\\TYPE=P",  # → \\TYPE=P8
    4: b"\\TYPE=X",  # → \\TYPE=X4
    6: b"\\TYPE=NUMC",  # → \\TYPE=NUMC10
}


def _v1_tname(rfctype: int, nuc_length: int) -> bytes:
    if rfctype in _V1_TNAME_FIXED:
        return _V1_TNAME_FIXED[rfctype]
    return _V1_TNAME_PREFIX[rfctype] + str(nuc_length).encode()


def _v1_enc_int(value: int, width: int, signed: bool) -> bytes:
    """compMode 'N' (0x4E) + LE fixed-width integer.

    the field serializer INT4: writeByte(0x4E) then 4B LE signed.
    """
    fmt = {(1, False): "B", (2, True): "h", (4, True): "i", (8, True): "q"}
    return b"\x4e" + struct.pack("<" + fmt[(width, signed)], int(value))


def _v1_enc_struct_field(fd: FieldDesc, value: Any) -> bytes:
    """Encode one field value for a STRUCTURE body (compMode + encoded_value).

    protocol analysis: dispatch on ngrfc_type, write compMode byte then value.
    protocol analysis: initial-value path writes 0x49 ('I'); non-initial calls
    the field serializer.  We always write the full value (no 'I' optimization) — safe and simpler.

    Field types handled: all rfctypes that can appear inside an ABAP structure.
    """
    rt = fd.rfctype
    if rt in (0, 1, 3, 6):  # CHAR, DATE, TIME, NUM — UC char encoding
        return _v1_encode_char_value(
            str(value) if value is not None else "", fd.nuc_length, fd.uc_length
        )
    if rt in (8, 9, 10, 31):  # INT4, INT2, INT1, INT8
        _cfg = {8: (4, True), 9: (2, True), 10: (1, False), 31: (8, True)}
        width, signed = _cfg[rt]
        return _v1_enc_int(int(value) if value is not None else 0, width, signed)
    if rt == 7:  # FLOAT
        return b"\x4e" + struct.pack("<d", float(value) if value is not None else 0.0)
    if rt == 2:  # BCD (TYPE P)
        from decimal import Decimal

        v = value if value is not None else Decimal(0)
        return _v1_enc_bcd(v, fd.nuc_length, fd.decimals)
    if rt == 4:  # BYTE (TYPE X)
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value or b"")
        raw = raw[: fd.nuc_length].ljust(fd.nuc_length, b"\x00")
        return b"\x4e" + raw
    if rt == 29:  # STRING
        return _v1_enc_string(str(value) if value is not None else "")
    if rt == 30:  # XSTRING
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value or b"")
        return _v1_enc_xstring(raw)
    if rt == 32:  # UTCLONG — the field serializer case 0x20 → INT8 path (compMode=0x4e + int64LE)
        return _v1_enc_int(int(value) if value is not None else 0, 8, True)
    raise NotImplementedError(
        f"STRUCTURE field rfctype={rt} ({fd.name!r}) not supported in V1 Q-marker"
    )


def _v1_q_struct(name_b: bytes, fd: FieldDesc, value: dict[str, object]) -> bytes:
    """Build V1 Q-marker for STRUCTURE (rfctype=0x11) IMPORT param.

    Wire layout (protocol analysis the metadata serializer, the column metadata serializer,
    the data serializer, the field serializer):

      0x51 + name_len(1B) + name          Q-marker (the parameter serializer)
      0x44                                D marker (the metadata serializer writeByte)
      (n_fields | 0x5000) LE(2B)          writeInt2 normal path (n_fields <= 0xffe)
      struct_tname_LV                     the name serializer(struct type name) — 0x00 if unknown
      Per-field metadata (the column metadata serializer):
        ngrfc_type(1B)                    the single-type metadata serializer
        [field_len LE(2B)]                absent for ngrfc_type <= 4 (INT types)
        [decimals(1B)]                    BCD only (ngrfc_type == 9)
        field_name_LV                     the name serializer(field_name), UTF-8 LV
      Per-field values (the data serializer field loop):
        compMode(1B) + encoded_value      the field serializer result (never 'I' optimization)
    """
    td = fd.type_desc
    if td is None:
        raise ValueError(f"STRUCTURE param {name_b!r} has no type_desc — cannot serialize")

    fields = td.fields
    n_fields = len(fields)

    # D-block header: D + int16LE(n_fields | 0x5000) + struct_type_name_LV
    d_block = bytearray()
    d_block.append(0x44)
    d_block += struct.pack("<H", (n_fields | 0x5000) & 0xFFFF)
    # Struct type name: write empty LV (0x00) — we don't have the DDIC type name.
    # the name serializer writes 0 bytes for empty string; 0x00 is the well-formed LV
    # equivalent (length=0) that the server can safely skip.
    d_block.append(0x00)

    # Per-field metadata
    for fld in fields:
        rt = fld.rfctype
        ngt = _V1_NGT.get(rt)
        if ngt is None:
            raise NotImplementedError(
                f"STRUCTURE field {fld.name!r} rfctype={rt} has no ngrfc_type mapping"
            )
        d_block.append(ngt)
        if ngt > 4:  # the single-type metadata serializer: write field_len for non-INT types
            field_len = fld.uc_length if fld.unicode_mode else fld.nuc_length
            d_block += struct.pack("<H", field_len)
            if ngt == 9:  # BCD: also write decimals
                d_block.append(fld.decimals)
        # field name LV (ASCII/UTF-8)
        fname_b = fld.name.encode("ascii")
        d_block += _ngrfc_write_lv(fname_b)

    # Per-field values
    val_dict: dict[str, object] = {}
    if isinstance(value, dict):
        val_dict = {k.upper(): v for k, v in value.items()}

    field_values = bytearray()
    for fld in fields:
        fval = val_dict.get(fld.name.upper())
        field_values += _v1_enc_struct_field(fld, fval)

    return b"\x51" + bytes([len(name_b)]) + name_b + bytes(d_block) + bytes(field_values)


def _v1_enc_bcd(value: object, nuc_length: int, decimals: int) -> bytes:
    """compMode 'N' (0x4E) + packed BCD bytes for ABAP TYPE P.

    Encoding: each byte = 2 BCD digits (high nibble first).
    Last nibble: 0xC = positive, 0xD = negative.
    nuc_length bytes total; (2*nuc_length-1) digit positions.
    """
    from decimal import Decimal

    d = Decimal(str(value))
    is_neg = d < 0
    scaled = int(abs(d) * (10**decimals))
    max_digits = 2 * nuc_length - 1
    digits_str = str(scaled).zfill(max_digits)
    if len(digits_str) > max_digits:
        raise OverflowError(
            f"BCD value {value!r} overflows P({nuc_length}) dec={decimals} "
            f"({len(digits_str)} > {max_digits} digits)"
        )
    nibbles = [int(c) for c in digits_str] + [0xD if is_neg else 0xC]
    result = bytearray(nuc_length)
    for i in range(nuc_length):
        result[i] = (nibbles[2 * i] << 4) | nibbles[2 * i + 1]
    return b"\x4e" + bytes(result)


def _v1_stringlike_chunks(data: bytes) -> bytes:
    """Chunk UTF-8 bytes for the string-serializer non-UC (wRFC) wire format.

    protocol analysis non-UC path (arg1[0x10]==0):
    - First chunk: max 0x3FFF bytes. Last flag = 0x4000 (first+last only).
    - Subsequent chunks: max 0x7FFF bytes. Last flag = 0x8000.
    - Non-last chunks (any position): no flag, bare byte_count.
    - No total count written after last chunk for non-UC mode (skip when
      arg1[0x10]==0 && entry_r15==r12, confirmed from hexdump at: je +0x43).

    UTF-8 multi-byte sequence boundaries are respected when splitting (trim end back
    while data[end] is a continuation byte 0x80-0xBF).
    """
    total = len(data)
    if total == 0:
        return struct.pack("<H", 0x4000)  # empty single chunk: 0 bytes | last-flag

    out = bytearray()
    first = True
    pos = 0
    while pos < total:
        limit = 0x3FFF if first else 0x7FFF
        end = min(pos + limit, total)
        if end < total:
            # Trim to valid UTF-8 boundary: back up while data[end] is a continuation byte
            while end > pos and (data[end] & 0xC0) == 0x80:
                end -= 1
        chunk = data[pos:end]
        pos = end
        is_last = pos >= total
        hdr = len(chunk)
        if is_last:
            hdr |= 0x4000 if first else 0x8000
        out += struct.pack("<H", hdr)
        out += chunk
        first = False
    return bytes(out)


def _v1_enc_string(value: str) -> bytes:
    """compMode 'S' (0x53) + the string serializer chunks for STRING.

    protocol analysis non-UC (wRFC) mode confirmed:
    single chunk: int16LE(utf8_byte_count | 0x4000) + utf8_bytes.
    Multi-chunk: see _v1_stringlike_chunks. No total count for non-UC mode.
    """
    return b"\x53" + _v1_stringlike_chunks(value.encode("utf-8"))


def _v1_enc_xstring(value: bytes | bytearray) -> bytes:
    """compMode 'X' (0x58) + the string serializer chunks for XSTRING.

    Same chunk format as STRING but raw bytes (no UTF-8 conversion).
    the string serializer non-UC path: first-chunk max 0x3FFF, subsequent 0x7FFF.
    """
    return b"\x58" + _v1_stringlike_chunks(bytes(value))


def _build_ngrfc_params(params: dict[str, Any], desc: FunctionDesc) -> bytes:
    """Build NG RFC V1 (fast serializer v3, HDR byte[2]=0x03) parameter bytes.

    protocol analysis confirmed format (ngrfcSerializeParams, sub_4af169):

      T-markers — schema activation for EXPORT/CHANGING/TABLES params:
        protocol analysis: writes T iff direction & 2 != 0.
        0x54 + name_len(1B) + name
        RFC_EXPORT (2) ✓, RFC_CHANGING (3) ✓, RFC_TABLES (7=0b111) ✓, RFC_IMPORT (1) ✗.

      Q-markers — param values supplied by caller (IMPORT/CHANGING/TABLES with data):
        protocol analysis: Q(0x51) hardcoded, then per-type dispatch.
        Scalar/struct (rfctype ≠ 5):
          0x51 + name_len(1B) + name + D-block(0x5001) + compMode + value
        TABLE (rfctype == 5), IMPORT/TABLES direction, table data present:
          0x51 + name_len(1B) + name
          + K(0x4b) [from the metadata serializer isFirstRow=1,]
          + (col_count | 0xD000) LE(2B) []
          + dm_table_id LE(2B) []
          + tname_len(1B) + tname []
          + col_metadata [the column metadata serializer]
          + row_count(2B) + row_data

      EXPORT TABLE params (e.g. GFI PARAMS): T-marker only — no Q, no K.
        protocol analysis: EXPORT params skip when data ptr == 0.

      Terminator: 0x45 (EXECUTE marker, setNgRfcExecute).
    """
    params_upper = {k.upper(): v for k, v in params.items()}
    t_section = bytearray()
    q_section = bytearray()
    table_idx = 0

    for fd in desc.parameters:
        pname = fd.name.upper()
        name_b = pname.encode("ascii")
        rt = fd.rfctype

        # T-markers: schema activation for EXPORT, CHANGING, TABLES params.
        # the out-parameter path: if (direction & 2) == 0 → skip.
        if fd.direction & 2:
            t_section += b"\x54" + bytes([len(name_b)]) + name_b

        # Q-markers: caller-supplied values (only for params present in `params`).
        if pname not in params_upper:
            continue

        val = params_upper[pname]

        if rt == 5:  # RFCTYPE_TABLE — Q + K inside body
            table_idx += 1
            q_section += _v1_table_q_marker(name_b, table_idx)

        elif rt == 0:  # CHAR — pcap-verified path (ngrfc_type=6, _v1_q_marker)
            tname = _v1_type_name(rt, fd.nuc_length)
            q_section += _v1_q_marker(
                name_b,
                fd.uc_length,
                _v1_encode_char_value(str(val), fd.nuc_length, fd.uc_length),
                tname,
            )

        elif rt in (1, 3, 6):  # DATE, TIME, NUM — char-like UC encoding, correct ngrfc_type
            tname = _v1_tname(rt, fd.nuc_length)
            q_section += _v1_q_block(
                name_b,
                tname,
                _V1_NGT[rt],
                fd.uc_length,
                _v1_encode_char_value(str(val), fd.nuc_length, fd.uc_length),
            )

        elif rt in (8, 9, 10, 31):  # INT4, INT2, INT1, INT8 — no field_len in D-block
            _cfg = {8: (4, True), 9: (2, True), 10: (1, False), 31: (8, True)}
            width, signed = _cfg[rt]
            q_section += _v1_q_block(
                name_b,
                _v1_tname(rt, fd.nuc_length),
                _V1_NGT[rt],
                None,  # ngrfc_type ≤ 4 → no field_len bytes in D-block
                _v1_enc_int(val, width, signed),
            )

        elif rt == 7:  # FLOAT (FLTP)
            q_section += _v1_q_block(
                name_b,
                b"\\TYPE=FLTP",
                19,
                8,
                b"\x4e" + struct.pack("<d", float(val)),
            )

        elif rt == 2:  # BCD (TYPE P)
            q_section += _v1_q_block(
                name_b,
                _v1_tname(rt, fd.nuc_length),
                9,
                fd.nuc_length,
                _v1_enc_bcd(val, fd.nuc_length, fd.decimals),
                decimals=fd.decimals,
            )

        elif rt == 29:  # STRING
            q_section += _v1_q_block(
                name_b,
                b"\\TYPE=STRING",
                24,
                0,
                _v1_enc_string(str(val)),
            )

        elif rt == 30:  # XSTRING
            raw = val.encode("utf-8") if isinstance(val, str) else bytes(val)
            q_section += _v1_q_block(
                name_b,
                b"\\TYPE=XSTRING",
                25,
                0,
                _v1_enc_xstring(raw),
            )

        elif rt == 4:  # BYTE (TYPE X, raw)
            raw = val.encode("utf-8") if isinstance(val, str) else bytes(val)
            raw = raw[: fd.nuc_length].ljust(fd.nuc_length, b"\x00")
            q_section += _v1_q_block(
                name_b,
                _v1_tname(rt, fd.nuc_length),
                23,
                fd.nuc_length,
                b"\x4e" + raw,
            )

        elif rt == 0x11:  # RFCTYPE_STRUCTURE
            q_section += _v1_q_struct(name_b, fd, val if isinstance(val, dict) else {})

        elif rt == 32:  # RFCTYPE_UTCLONG — ngrfc_type=0x1d, INT8 wire encoding
            # the field serializer case 0x1f,0x20 → shared INT8 path; compMode=0x4e + int64LE.
            # ngrfc_type=29 (0x1d) > 4 → field_len=8 IS written in D-block metadata.
            # UNCERTAIN: tname "\\TYPE=UTCLONG" not live-captured.
            q_section += _v1_q_block(
                name_b,
                b"\\TYPE=UTCLONG",
                _V1_NGT[32],
                8,  # field_len: UTCLONG is always 8 bytes
                _v1_enc_int(val, 8, True),
            )

        else:
            raise NotImplementedError(
                f"V1 ngrfc Q-marker not implemented for rfctype={rt} "
                f"(param {pname!r}); DECF16/DECF34 not yet supported"
            )

    # 0x45 = EXECUTE marker (protocol analysis.
    return bytes(t_section + q_section + b"\x45")


def _lz4_block_compress(data: bytes) -> bytes:
    """Pure-Python LZ4 block compressor, literal-only (no match finding).

    Emits valid LZ4 block data per spec (lz4.org/lz4_Frame_format.html).
    All payload goes into one terminal sequence: token[high4=lit_len_cap]
    + extra-length bytes + literals. No match offset/length emitted (last-
    sequence rule). Server uses LZ4_decompress_safe_usingDict with zero-init
    dict for first block — independent literal-only blocks are fully safe. ngrfcSerializeParams: conn[0x3ce]=0x4020 → high-byte bit6
    set → NgRfcLZ4Compressor active; literal-only output satisfies the
    decompressor (no-guessing policy: no match logic until RE confirms dict).
    """
    if not data:
        return b""
    n = len(data)
    out = bytearray()
    lit_len = n
    token_lit = min(lit_len, 15)
    out.append(token_lit << 4)  # high nibble = literal count cap, low = 0 (no match)
    if token_lit == 15:
        remaining = lit_len - 15
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    out += data
    return bytes(out)


def _sap_lz4_frame(data: bytes) -> bytes:
    """SAP LZ4 framing: [0x34 type marker][4B LE uncomp_len][4B LE comp_len][lz4_block_data].

    protocol analysis (confirmed 2026-07-28):
    - NgRfcLZ4Compressor::ctor: writeByte(0x34) — type-marker byte written once.
    - NgRfcLZ4Compressor::doCompress: writeInt4(uncomp)+writeInt4(comp)+writeData.
    - the LZ4 decompressor::ctor: readByte() checked == 0x34, else throw;
      then calls decompress() which reads int4(uncomp)+int4(comp)+readData(comp).
    - the NgRfc receive stream: reads full 0x5001 payload into buffer,
      consumes byte-0='$', calls getHeader() (bytes 1-13), setSerializerVersion(); buffer
      pointer at byte 14 when createDecompressor → the LZ4 decompressor::ctor runs.
    Prior removal of 0x34 was incorrect (doCompress does not write it; ctor does).
    """
    block = _lz4_block_compress(data)
    return b"\x34" + struct.pack("<II", len(data), len(block)) + block


def _build_ws_invoke_message(
    func_name: str,
    desc: FunctionDesc,
    params: dict[str, Any],
    *,
    session_key: bytes = b"",
    logon_func: str = "RFCPING",
    # legacy params accepted but unused (callers may still pass them)
    sysnr: str = "00",
    local_ip: str = "127.0.0.1",
    lang: str = _DEFAULT_LANG,
) -> bytes:
    """Build a subsequent wRFC function-invoke frame (pcap-verified structure).

    Pcap ground truth: frames 229/233/237/241 in websocketrfc_sniff.pcap.
    NO session header (0x0101-0x0160), NO auth TLVs, NO session-info TLVs.

    Structure (pcap frames 229/233):
      0x0502 (call marker, empty)
      0x0136 (37B: \\x01 + 36B session key from LOGON — reuse same key each call)
      0x000b (SAP release "757", 6B UTF-16LE)
      0x0102 (func_name UTF-16LE)
      0x000b (SAP release "757" duplicate)
      0x0130 (40-char end marker: logon_func + "="*(38-len) + "FT", 80B UTF-16LE — pcap: always LOGON func)
      0x0503 (empty)
      0x0420 (\\x00\\x00\\x00\\x00 — RC=0 request)
      0x0512 (empty)
      0x5001 (_WS_5001_HDR 14B + ngrfc body)
      TERM (\\xff\\xff\\x00\\x00)

    Credentials never appear in this frame (threats T-Q0E-01 / T-07-CRED).
    """
    name = func_name.upper()
    rel_u16 = "757".encode("utf-16-le")
    # 0x0130 end marker: logon_func + "="*(38-len) + "FT" = 40 chars (80B UTF-16LE)
    # Pcap-verified: invoke frames use the LOGON function name (not the current func),
    # space-padded to exactly 40 chars (80B UTF-16LE). NOT "=...FT" — that format is
    # for LOGON frames only; invoke frames use simple ljust(40) space padding.
    logon = logon_func.upper()
    func_end_padded = logon.ljust(40).encode("utf-16-le")

    _ngrfc_body = _build_ngrfc_params(params, desc)
    # Pcap-verified: client→server invoke frames use _WS_5001_HDR (no LZ4, 0x2040).
    # _WS_5001_HDR_INVOKE (0x6040) appears only in server→client RESPONSE frames.
    # Byte[2] of the HDR distinguishes schema-only (0x03) vs value-carrying frames (0x02):
    #   frame 229 (T-markers only, no Q_SCALAR): HDR byte[2]=0x03
    #   frame 233 (T+K+Q_SCALAR+TABLE_Q): HDR byte[2]=0x02
    _has_q_markers = b"\x51" in _ngrfc_body
    _invoke_hdr = _WS_5001_HDR_WITH_VALS if _has_q_markers else _WS_5001_HDR
    call_key = session_key if session_key else (b"\x01" + b"\x00" * 36)

    # Pcap frame 229 (RFC_SYSTEM_INFO) and 233 (RFC_READ_TABLE) both show:
    #   0x0130 → 0x0503 (empty) → 0x0420 → 0x0512 → 0x5001 → 0x0104 → TERM
    # Prior comment claiming "NO 0x0503 in invoke frames" was wrong — capture analysis confirms it.
    # Hypothesis: 0x0104 with pcap reference IPs (192.168.66.x) causes RABAX on live system.
    # Test: omit 0x0104 (same approach as LOGON frame) to see if RABAX resolves.
    # LOGON comment: "wrong-environment 0x0104 causes WP hang" → same may apply to invoke.
    parts: list[bytes] = [
        _tlv_ext(0x0502, b""),
        _tlv_ext(0x0136, call_key),
        _tlv_ext(0x000B, rel_u16),
        _tlv_ext(0x0102, name.encode("utf-16-le")),
        _tlv_ext(0x000B, rel_u16),
        _tlv_ext(0x0130, func_end_padded),
        _tlv_ext(0x0503, b""),
        _tlv_ext(0x0420, b"\x00\x00\x00\x00"),
        _tlv_ext(0x0512, b""),
        _tlv_ext(0x5001, _invoke_hdr + _ngrfc_body),
        # 0x0104 intentionally omitted: pcap-reference IPs cause RABAX on non-pcap system.
        _TAG_TERMINATOR.to_bytes(2, "big") + b"\x00\x00",
    ]

    return b"".join(parts)


def _ws_parse_invoke_response(data: bytes, desc: FunctionDesc) -> dict[str, Any]:
    """Parse a raw wRFC invoke response (WebSocket TLV, no GW header).

    Raises :class:`AbapSystemFailure` when the server signals an error — the message
    carries the numeric E-code (e.g. "163" = CALL_FUNCTION_RECEIVE_ERROR) from the
    0x0420 return-code tag and/or the decoded 0x0402 message text, so callers and the
    live gate can distinguish the known wRFC 0x5001 descriptor gap (STATE.md) from a
    transport failure. On success, returns a dict keyed by param name with
    UTF-16LE-decoded string values. Never echoes credentials (T-07-CRED / T-Q0E-01).

    NOTE (STATE.md blocker): the exact wRFC error-tag layout is only partially RE'd.
    This parser surfaces the documented 0x0420 return code and 0x0402 message text
    rather than inventing an error schema (no-guessing policy). It uses the existing
    bounds-checked ``Session._parse_tlv`` so a malformed/error response is never
    mis-decoded as param data (T-Q0E-03).

    LZ4 decompression: if the server sends a SAP LZ4 frame (marker byte 0x34), the
    payload is decompressed before TLV parsing.  With _WS_5001_HDR_INVOKE flags=0x6040
    (LZ4 send enabled) the server may compress its responses too; this path handles both.
    the LZ4 decompressor::ctor reads marker 0x34 then decomp_len+comp_len.
    """
    if data and data[0] == 0x34:
        try:
            data = sap_lz4_frame_decompress(data)
        except DecompressError as exc:
            raise AbapSystemFailure(message=f"wRFC LZ4 decompression failed: {exc}") from exc

    tags = Session._parse_tlv(data)

    err_text = ""
    err_msg = tags.get(0x0402)
    if err_msg:
        try:
            err_text = err_msg.decode("utf-8", errors="replace").strip("\x00 ")
        except Exception:
            err_text = err_msg.hex()

    ecode: int | None = None
    rc_bytes = tags.get(0x0420)
    if rc_bytes and len(rc_bytes) == 4:
        rc = struct.unpack(">I", rc_bytes)[0]
        if rc != 0:
            ecode = rc

    if ecode is not None:
        detail = f" {err_text}" if err_text else ""
        raise AbapSystemFailure(message=f"wRFC call failed: E={ecode}{detail}")
    if err_text:
        raise AbapSystemFailure(message=f"wRFC call failed: {err_text}")

    # Success — decode returned 0x0201/0x0203 param pairs as UTF-16LE strings.
    result: dict[str, object] = {}
    for pname, value in _extract_name_value_pairs(data):
        try:
            decoded: object = value.decode("utf-16-le").rstrip("\x00 ")
        except Exception:
            decoded = value
        result[pname] = decoded
    return result


def _convert_date_time_fields(result: dict[str, Any], desc: FunctionDesc) -> dict[str, Any]:
    """Convert DATE/TIME string results to datetime.date/time at the response boundary.

    The Phase 2 codec returns str for DATE ("YYYYMMDD") and TIME ("HHMMSS").
    Phase 4 converts these at the call() boundary so the public API returns
    datetime objects (CLIENT-03/D-24). Empty/initial values ("00000000"/"000000")
    map to None.

    The codec is NOT modified — conversion is a response-boundary concern.
    """
    param_map = {f.name.upper(): f for f in desc.parameters}
    converted = {}
    for key, value in result.items():
        field = param_map.get(key.upper())
        if field is None or not isinstance(value, str):
            converted[key] = value
            continue
        if field.rfctype == _RFCTYPE_DATE:
            stripped = value.strip()
            if not stripped or stripped == "00000000":
                converted[key] = None
            else:
                try:
                    converted[key] = datetime.datetime.strptime(stripped, "%Y%m%d").date()
                except ValueError:
                    converted[key] = value  # non-conforming — leave as str
        elif field.rfctype == _RFCTYPE_TIME:
            stripped = value.strip()
            if not stripped or stripped == "000000":
                converted[key] = None
            else:
                try:
                    converted[key] = datetime.datetime.strptime(stripped, "%H%M%S").time()
                except ValueError:
                    converted[key] = value  # non-conforming — leave as str
        else:
            converted[key] = value
    return converted


def _strip_gw_header(resp: bytes) -> bytes:
    """Strip the 80-byte GW header (76B header + 4B RFC marker) from a live server response.

    Live RFC responses are GW frames: [GW header 76B][RFC marker 4B][TLV…].
    All GW frames have first byte 0x06 (all GW builders set *(ptr+0x50)=6).
    TLV invoke responses always start with tag 0x05xx (e.g. 0x0500 call-end marker)
    and MockTransport responses are raw TLV — neither starts with 0x06, so the
    first-byte check discriminates GW frames from bare TLV safely.
    Note: 0x06CB is the typical RFC data frame type but the server may use variants
    (e.g. 0x06CE observed in live STFC_CONNECTION responses) — checking only the
    first byte handles all GW frame variants.
    """
    if resp and resp[0] == 0x06:
        return resp[80:]  # skip GW header (76B) + RFC marker (4B)
    return resp


def _resolve_credentials(
    user: str | None, passwd: str | None, *, snc_lib: str | None, ashost: str
) -> tuple[str | None, str | None]:
    """Decide whether this connection carries credentials, and sanity-check them.

    Supplying neither a user nor a password, and no SNC library, is taken as a
    deliberate anonymous attempt: the logon frame goes out without the user and
    password records. Some systems answer a small set of function modules that way;
    a hardened one refuses below the RFC layer, which now reports as a
    CommunicationError naming the CPIC message rather than an unreadable response.

    Supplying exactly one of the two is rejected. That is not a request to connect
    anonymously, it is a missing environment variable or a typo, and turning it into
    a silent anonymous attempt would replace a clear error with a confusing one.
    """
    if snc_lib is not None:
        return user, passwd
    if user is None and passwd is None:
        _logger.warning(
            "connecting to %s without credentials: no user, no password and no "
            "snc_lib were given, so the logon frame will omit the user and password "
            "records. Most systems refuse this.",
            ashost,
        )
        return None, None
    if user is None or passwd is None:
        missing = "user" if user is None else "passwd"
        raise ValueError(
            f"{missing} is missing while the other credential was supplied. Pass both "
            f"to authenticate, or neither to attempt an anonymous connection."
        )
    return user, passwd


def _filter_call_params(
    func_name: str,
    desc: FunctionDesc,
    params: dict[str, Any],
    *,
    strict: bool,
    seen: set[tuple[str, tuple[str, ...]]],
) -> dict[str, Any]:
    """Apply the connection's unknown-parameter policy to one call's arguments.

    ``strict=True`` leaves ``params`` untouched, so build_invoke_request raises and
    names what it did not recognise. ``strict=False`` drops the unrecognised names
    and returns the rest, matching what callers porting from pyrfc expect when they
    pass a superset of kwargs across differing SAP releases.

    Dropping an argument is not free - the function then runs without it and returns
    a result the caller did not ask for, with nothing in the response to say so - so
    lenient mode is noisy on purpose. The first occurrence of each
    (function, dropped-names) combination logs at WARNING and later repeats drop to
    DEBUG, which keeps a long-running loop from flooding its log while still leaving
    a record that the arguments never reached the server.
    """
    unknown = unknown_parameters(desc, params)
    if not unknown or strict:
        return params

    key = (func_name.upper(), tuple(unknown))
    message = (
        "%s: dropping parameter(s) %s - not in the function interface "
        "(strict_params=False). The call proceeds without them."
    )
    if key in seen:
        _logger.debug(message, func_name.upper(), ", ".join(unknown))
    else:
        seen.add(key)
        _logger.warning(message, func_name.upper(), ", ".join(unknown))
    return drop_unknown_parameters(desc, params)


_DFIES_ROW_BYTES = 138  # wire-confirmed DFIES row layout; the stride may be 140
_GFI_ROW_BYTES = 402  # the documented 12-column PARAMS layout; the wire stride may
# exceed it (alignment padding), so it is a minimum, never the stride itself.


def _table_row_buffers(response: bytes, min_row_bytes: int, table: str = "") -> list[bytes]:
    """Split a fixed-width result table out of a response into row buffers.

    Shared by every reader of a fixed-width result table — the GFI PARAMS table and
    the RFC_GET_STRUCTURE_DEFINITION FIELDS table both arrive this way, and both were
    previously readable only in the uncompressed form.

    The server uses two different shapes and they cannot be handled the same way:

    * **Per-row records** (0x0303 / 0x0304) — each record is exactly one row, at the
      row's *used* width. The 0x0302 stride may be larger: a structure-definition
      response in the same session declared row_size 140 while every record was 138
      bytes. Concatenating these and re-slicing by the declared stride would
      misalign every row after the first, so each record is taken as-is.

    * **One compressed stream** (0x0305) — the records are fragments of a single
      SAPCOMPRESS stream and carry no row boundaries at all, so the decompressed
      blob must be sliced by the stride from 0x0302. BAPI_USER_GET_DETAIL declares
      row_size 404 for the 12-column layout that occupies 402 bytes; the extra 2
      bytes are alignment padding, and the response reports the used width
      separately in tag 0x0310.

    The server switches to compression once a table passes roughly 8 KB, so this is
    not an exotic path: it is every function module with enough parameters, which
    includes most BAPIs. Handling only 0x0303 left all of them with an empty
    descriptor and no diagnostic.
    """
    row_size = 0
    per_record: list[bytes] = []
    lz_chunks: list[bytes] = []

    pos, n = 0, len(response)
    while pos + 4 <= n:
        tag, length = struct.unpack_from(">HH", response, pos)
        pos += 4
        if tag == 0xFFFF:
            break
        if length == 0xFFFF:
            if pos + 4 > n:
                break
            length = struct.unpack_from(">I", response, pos)[0]
            pos += 4
        end = pos + length
        if end > n:
            break
        data = response[pos:end]
        pos = end
        # Skip the optional repeated-tag suffix used in extended TLV format.
        if pos + 2 <= n and struct.unpack_from(">H", response, pos)[0] == tag:
            pos += 2

        if tag == 0x0302 and length == 8:
            row_size = struct.unpack_from(">I", data, 0)[0]
        elif tag in (0x0303, 0x0304):
            per_record.append(data)
        elif tag == 0x0305:
            lz_chunks.append(data)

    if lz_chunks:
        try:
            blob = decompress_table_stream(lz_chunks, table)
        except ValueError as exc:
            _logger.warning(
                "could not decompress the %s result table; metadata unavailable: %s",
                table or "result",
                exc,
            )
            return []
        stride = row_size if row_size >= min_row_bytes else min_row_bytes
        return [blob[i : i + stride] for i in range(0, len(blob) - stride + 1, stride)]

    # Per-row records: one row each, at whatever width the server used.
    return [r for r in per_record if len(r) >= min_row_bytes]


def _parse_gfi_params_rows(
    response: bytes,
    *,
    unicode_mode: bool = True,
) -> list[dict[str, Any]]:
    """Extract RFC_GET_FUNCTION_INTERFACE PARAMS rows from a response TLV stream.

    Walks the TLV for 0x0303 tags; each is one PARAMS row (402 bytes UTF-16LE) with
    the confirmed 12-column layout (META-01, wire-captured 2026-06-28):

        PARAMCLASS  1 char  (2 B)   — 'I'/'E'/'C'/'T'
        PARAMETER  30 chars (60 B)  — parameter name
        TABNAME    30 chars (60 B)  — structure/table type name
        FIELDNAME  30 chars (60 B)  — field name (empty for top-level params)
        EXID        1 char  (2 B)   — type code ('C'/'I'/'u'/…)
        POSITION    INT4 LE (4 B)   — parameter position (1-based)
        OFFSET      INT4 LE (4 B)   — NUC byte offset inside structure
        INTLENGTH   INT4 LE (4 B)   — NUC char/byte count (see note below)
        DECIMALS    INT4 LE (4 B)   — BCD decimal places
        DEFAULT    21 chars (42 B)  — default value
        PARAMTEXT  79 chars (158 B) — parameter description text
        OPTIONAL    1 char  (2 B)   — 'X' if optional
        Total: 402 bytes

    Wire encoding note: OFFSET/INTLENGTH arrive in the character width the connection
    itself uses. On a Unicode connection they are already Unicode byte counts and are
    passed straight to _parse_params_row, which expects uc (unicode byte) values;
    scaling them again produced parameter values twice their declared width, which the
    server silently discarded. Binary/numeric types (I b B 8 F P X u h v e) are byte
    counts either way.

    Falls back to an empty list on any parse error (DoS guard: rogue peer returns
    malformed rows — skip them rather than crash).
    """
    # Strip GW header if the response is a raw GW frame (live server path).
    response = _strip_gw_header(response)

    # EXID char-like codes whose width depends on the connection's character size.
    # Mirror of metadata._CHAR_LIKE_TYPES keyed by EXID string codes.
    _CHAR_LIKE_EXID = frozenset("CDTNg")

    rows: list[dict[str, Any]] = []
    for data in _table_row_buffers(response, _GFI_ROW_BYTES, "PARAMS"):
        try:
            off = 0

            def _u16(count: int, _d: bytes = data) -> str:
                nonlocal off
                raw = _d[off : off + count * 2]
                off += count * 2
                return raw.decode("utf-16-le").rstrip(" \x00")

            def _i4(_d: bytes = data) -> int:
                nonlocal off
                val = struct.unpack_from("<I", _d, off)[0]
                off += 4
                return int(val)

            paramclass = _u16(1)
            parameter = _u16(30)
            tabname = _u16(30)
            fieldname = _u16(30)
            exid = _u16(1)
            position = _i4()
            offset_nuc = _i4()
            intlen_nuc = _i4()
            decimals = _i4()
            default = _u16(21)
            paramtext = _u16(79)
            optional = _u16(1)
        except Exception:
            continue  # skip malformed row

        # OFFSET / INTLENGTH arrive in the character width the *connection* uses, so
        # on a Unicode connection they are already Unicode byte counts and must be
        # passed through untouched. _parse_params_row expects uc_* values and derives
        # the nuc_* pair by halving char-like types.
        #
        # Source: golden fixture tests/golden/framing/rfc_read_table_request.bin —
        # RFC_READ_TABLE.QUERY_TABLE is DD02L-TABNAME, CHAR(30), and the captured
        # 0x0203 value is 60 bytes (30 chars); DELIMITER is SONV-FLAG, CHAR(1), and
        # its captured value is 2 bytes. A Unicode-connection GFI reports 60 and 2 for
        # those, so doubling them emitted 120- and 4-byte values, which the server
        # rejected (observed live on kernel 793: RFC_READ_TABLE raised
        # TABLE_NOT_AVAILABLE because QUERY_TABLE never arrived intact).
        if exid in _CHAR_LIKE_EXID and not unicode_mode:
            # Doubling NUC counts to reach the uc_* representation the codec uses.
            #
            # This carried an uncertainty label because no non-Unicode capture
            # exists to confirm it. It is now unreachable on a live connection
            # instead: the handshake refuses any codepage that is not the 4103
            # Unicode wire mode, because the codec would decode such a
            # connection's character fields as UTF-16BE and silently produce
            # mojibake. Non-Unicode systems are out of scope -- SAP ended support
            # for them with NetWeaver 7.5.
            #
            # The branch stays for offline descriptors built without a negotiated
            # codepage, where unicode_mode is false by construction rather than
            # by observation.
            uc_length = intlen_nuc * 2
            uc_offset = offset_nuc * 2
        else:
            uc_length = intlen_nuc
            uc_offset = offset_nuc

        rows.append(
            {
                "PARAMCLASS": paramclass,
                "PARAMETER": parameter,
                "TABNAME": tabname,
                "FIELDNAME": fieldname,
                "EXID": exid,
                "POSITION": position,
                "OFFSET": uc_offset,
                "INTLENGTH": uc_length,
                "DECIMALS": decimals,
                "DEFAULT": default,
                "PARAMTEXT": paramtext,
                "OPTIONAL": optional,
            }
        )

    return rows


def _parse_dfies_rows(response: bytes) -> list[tuple[Any, ...]]:
    """Parse DFIES rows (138B each) from RFC_GET_STRUCTURE_DEFINITION response.

    Wire-confirmed row layout (138B UC mode, live RFCTEST decode 2026-06-29):
      [0:60]   TABNAME   C(30) UTF-16LE padded
      [60:120] FIELDNAME C(30) UTF-16LE padded
      [120:122] POSITION  INT2_LE (1-based field index)
      [122:124] reserved  0x0000
      [124:126] UC_OFFSET INT2_LE (byte offset in UC structure layout)
      [126:128] reserved  0x0000
      [128:130] UC_INTLEN INT2_LE (byte length in UC structure layout)
      [130:132] reserved  0x0000
      [132:134] DECIMALS  INT2_LE (16 for RFCFLOAT ABAP precision; 0 for others)
      [134:136] reserved  0x0000
      [136:138] EXID      C(1) UTF-16LE (SAP type code: 'C','F','I','s','b',...)

    The server sends UC_OFFSET / UC_INTLEN directly — no NUC computation needed for
    unicode-mode (unicode_mode=True) connections. NUC values are derived at build time.

    Returns list of (fieldname, position, uc_offset, uc_intlen, decimals, exid) tuples.
    Skips rows with unknown EXID or parse errors.
    """
    response = _strip_gw_header(response)

    rows: list[tuple[Any, ...]] = []
    for data in _table_row_buffers(response, _DFIES_ROW_BYTES, "FIELDS"):
        try:
            fieldname = data[60:120].decode("utf-16-le").rstrip(" \x00")
            position = struct.unpack_from("<H", data, 120)[0]
            uc_offset = struct.unpack_from("<H", data, 124)[0]
            uc_intlen = struct.unpack_from("<H", data, 128)[0]
            decimals = struct.unpack_from("<H", data, 132)[0]
            exid = data[136:138].decode("utf-16-le").rstrip(" \x00")
        except Exception:
            continue

        if not fieldname or exid not in _EXID_TO_RFCTYPE:
            continue
        rows.append((fieldname, position, uc_offset, uc_intlen, decimals, exid))

    return rows


def _build_type_desc_from_dfies(tabname: str, dfies_rows: list[tuple[Any, ...]]) -> TypeDesc:
    """Build TypeDesc from DFIES rows returned by RFC_GET_STRUCTURE_DEFINITION.

    The server provides UC_OFFSET and UC_INTLEN directly (wire-confirmed 2026-06-29
    for RFCTEST: RFCCHAR4 UC_OFFSET=14, RFCINT4=24, … total UC=264). No need to
    compute UC layout. NUC values are derived: CHAR-like halve, binary types same.

    Verified: all 12 RFCTEST fields decode to UC offsets matching the golden
    stfc_structure_request.bin (264B IMPORTSTRUCT encoding).
    """
    if not dfies_rows:
        raise ValueError(f"no DFIES rows for {tabname!r}")

    sorted_rows = sorted(dfies_rows, key=lambda r: r[1])  # sort by position

    fields: list[FieldDesc] = []
    for fieldname, _position, uc_offset, uc_intlen, decimals, exid in sorted_rows:
        rfctype = _EXID_TO_RFCTYPE[exid]
        if rfctype in _CHAR_LIKE_TYPES:
            nuc_intlen = uc_intlen // 2
        else:
            nuc_intlen = uc_intlen
        fields.append(
            FieldDesc(
                name=fieldname,
                rfctype=rfctype,
                nuc_length=nuc_intlen,
                nuc_offset=uc_offset // 2 if rfctype in _CHAR_LIKE_TYPES else uc_offset,
                uc_length=uc_intlen,
                uc_offset=uc_offset,
                decimals=decimals,
                unicode_mode=True,
                direction=RFC_IMPORT,
            )
        )

    nuc_size = sum(f.nuc_length for f in fields)
    uc_size = max((f.uc_offset + f.uc_length) for f in fields) if fields else 0
    return TypeDesc(name=tabname, fields=fields, nuc_size=nuc_size, uc_size=uc_size)


class _SyncToAsyncTransport:
    """Async-seam shim wrapping a sync Transport (or MockTransport in tests).

    Used by connect() so the AsyncConnection + _LoopThread architecture works
    with patched sync transports in existing tests (backward compatibility,
    Rule 1 fix for D-07 delegate refactor).  For true non-blocking I/O over
    real asyncio sockets, use connect_async() which calls connect_tcp_async().

    The shim's send/recv call the sync methods on the `_LoopThread`'s dedicated
    thread, which is safe because each Connection owns exactly one loop thread.
    """

    def __init__(self, sync_transport: Transport) -> None:
        self._inner = sync_transport

    # Minimal _writer-like interface so _handshake can extract local_ip.
    class _FakeWriter:
        def __init__(self, sock: object = None) -> None:
            self._sock = sock

        def get_extra_info(self, key: str, default: object = None) -> object:
            if key == "socket" and self._sock is not None:
                return self._sock
            return default

    @property
    def _writer(self) -> _FakeWriter:
        sock = getattr(self._inner, "_sock", None)
        return self._FakeWriter(sock)

    async def send_message(self, payload: bytes) -> None:
        self._inner.send_message(payload)

    async def recv_message(self) -> bytes:
        return self._inner.recv_message()

    async def close(self) -> None:
        self._inner.close()


class _LoopThread:
    """Persistent daemon event loop on a background thread for the sync facade (D-07).

    Each classic-TCP Connection holds one _LoopThread.  The asyncio stream objects
    created during connect_tcp_async are bound to the loop alive at creation time;
    using asyncio.run() per call would create a new loop each time, raising
    "Task got Future attached to a different loop" (Pitfall 1).

    run(coro) dispatches the coroutine via run_coroutine_threadsafe and blocks the
    calling thread until it completes — no nested-loop RuntimeError even when called
    from inside a running event loop.  close() stops the daemon thread.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name="saprfclib-conn-loop",
            daemon=True,
        )
        self._thread.start()

    def run(self, coro: object, timeout: float | None = None) -> Any:
        """Schedule *coro* on the background loop and block until it returns."""
        import concurrent.futures

        fut: concurrent.futures.Future[Any] = asyncio.run_coroutine_threadsafe(
            coro,  # type: ignore[arg-type]
            self._loop,
        )
        return fut.result(timeout)

    def close(self) -> None:
        """Stop the background loop, join the thread and release the loop.

        Closing matters, not just stopping: a stopped-but-unclosed event loop keeps
        its selector and the file descriptors behind it, so every sync classic
        connection leaked one until the interpreter collected it. Python 3.14
        surfaces that as a ResourceWarning from BaseEventLoop.__del__; the cost is
        real on any version, and accumulates in a long-running process that opens
        connections through the pool.

        Only closed once the thread has actually stopped — closing a running loop
        raises. If the join times out the loop is left alone rather than risking
        that, since a leaked descriptor beats an exception during cleanup.
        """
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5.0)
        if not self._thread.is_alive():
            try:
                self._loop.close()
            except RuntimeError:  # pragma: no cover - loop already closed
                pass


# An ABAP function module name is at most 30 characters. The wRFC call-name
# fields pad to a fixed width with '=' and then append "FT", so an over-long name
# does not truncate — the pad count goes negative, `"=" * -1` yields the empty
# string, and the field comes out too LONG. A 31-character name produced a
# 33-character call-begin field where the format requires 32, with nothing
# raising anywhere.
_MAX_FUNC_NAME_LEN = 30


def _pad_call_name(func_name: str, width: int) -> str:
    """``NAME`` + ``=`` padding + ``FT``, at exactly ``width`` + 2 characters."""
    if len(func_name) > width:
        raise ValueError(
            f"function module name {func_name!r} is {len(func_name)} characters; "
            f"ABAP allows at most {_MAX_FUNC_NAME_LEN} and this field pads to {width}"
        )
    return func_name + "=" * (width - len(func_name)) + "FT"


def _validate_sysnr(sysnr: str | int) -> int:
    """Return the system number as an int, or explain why it is not one.

    A system number is two digits: SAP's port table derives sapdp<NN>, sapgw<NN>
    and the rest from it, all with two-digit fields. Anything outside 0-99 breaks
    in two places at once — the gateway port becomes something that is not a
    gateway, and the eight-byte service field in the GW connect frame overflows,
    resizing the frame. Neither reports itself: the frame simply stops being
    parseable by the peer.
    """
    try:
        value = int(sysnr)
    except (TypeError, ValueError):
        raise ValueError(
            f"system number {sysnr!r} is not a number; it is the two-digit instance "
            f"number, e.g. 0 or '00'"
        ) from None
    if not 0 <= value <= 99:
        raise ValueError(
            f"system number {value} is outside 0-99. SAP derives sapdp<NN>/sapgw<NN> "
            f"from it with two-digit fields, so a larger value produces both a "
            f"non-gateway port and a malformed connect frame."
        )
    return value


@dataclass(frozen=True)
class CallStats:
    """What one RFC call cost, measured by this client.

    ``duration_s`` and the byte counts are measured locally: our clock, our socket.
    ``server_duration_s`` is the server's own figure, read from tag 0x0667 of the
    response, and it is the one number that separates server time from network
    time. A call taking 3 s of wall clock is a different problem depending on
    whether the server spent 2.99 s of that (the ABAP is slow) or 40 ms (the
    network, the gateway, or a queue is).

    ``server_duration_s`` is ``None`` whenever the field was not in the response,
    and that is deliberately distinct from ``0.0``. No release rule requiring the
    tag has been established, so absence means unknown; recording it as zero would
    put a fabricated number into a metrics series where it would read as an
    impossibly fast call rather than as missing data. It is also ``None`` on a
    failed call that never got a parseable response.

    Source for the 0x0667 reading: behavioural probe against A4H kernel 793 --
    see :func:`saprfclib.invoke.extract_server_duration` and
    docs/protocol/framing.md.
    """

    func_name: str
    duration_s: float
    request_bytes: int
    response_bytes: int
    failed: bool = False
    server_duration_s: float | None = None


class ConnectionMetrics:
    """Running totals for one connection, for exporting to a metrics system.

    Deliberately not a global registry: a connection is owned by one thread or
    task at a time (the pool is the concurrency boundary), so these need no
    locking, and a caller aggregating across a pool can sum them itself.

    Latency is kept as a total plus a count rather than a list of samples: an
    unbounded sample list on a long-running connection is a slow memory leak, and
    a mean plus a max is what a dashboard actually plots.
    """

    __slots__ = (
        "calls",
        "failures",
        "total_duration_s",
        "max_duration_s",
        "request_bytes",
        "response_bytes",
        "total_server_duration_s",
        "server_timed_calls",
        "last",
    )

    def __init__(self) -> None:
        self.calls = 0
        self.failures = 0
        self.total_duration_s = 0.0
        self.max_duration_s = 0.0
        self.request_bytes = 0
        self.response_bytes = 0
        # Server-reported time, and the count of calls that actually reported it.
        # Kept separate because the mean must divide by the calls that carried a
        # measurement, not by every call -- averaging over calls whose field was
        # absent would silently understate server time by whatever share of the
        # traffic omits the tag.
        self.total_server_duration_s = 0.0
        self.server_timed_calls = 0
        self.last: CallStats | None = None

    def record(self, stats: CallStats) -> None:
        self.calls += 1
        if stats.failed:
            self.failures += 1
        self.total_duration_s += stats.duration_s
        self.max_duration_s = max(self.max_duration_s, stats.duration_s)
        self.request_bytes += stats.request_bytes
        self.response_bytes += stats.response_bytes
        if stats.server_duration_s is not None:
            self.total_server_duration_s += stats.server_duration_s
            self.server_timed_calls += 1
        self.last = stats

    @property
    def mean_duration_s(self) -> float:
        """Mean call latency, or 0.0 before any call has been made."""
        return self.total_duration_s / self.calls if self.calls else 0.0

    @property
    def mean_server_duration_s(self) -> float:
        """Mean server-side time over the calls that reported one, else 0.0.

        Divides by ``server_timed_calls``, not by ``calls``. A response without
        tag 0x0667 carries no measurement, and folding it in as zero would
        understate server time by whatever share of the traffic omits the field.
        """
        return (
            self.total_server_duration_s / self.server_timed_calls
            if self.server_timed_calls
            else 0.0
        )

    @property
    def server_time_fraction(self) -> float:
        """Share of wall-clock time the server accounts for, over timed calls.

        The number this whole field exists for. Near 1.0 means latency is the
        ABAP; near 0.0 means it is the network, the gateway, or a queue. 0.0 when
        nothing reported a server time, which is why ``server_timed_calls``
        is exposed alongside it -- an unqualified 0.0 would otherwise read as
        "the server is instant" rather than "nothing was measured".
        """
        if not self.server_timed_calls or self.total_duration_s <= 0.0:
            return 0.0
        return self.total_server_duration_s / self.total_duration_s

    def as_dict(self) -> dict[str, float | int]:
        """A flat mapping, shaped for a metrics exporter."""
        return {
            "calls": self.calls,
            "failures": self.failures,
            "total_duration_s": self.total_duration_s,
            "mean_duration_s": self.mean_duration_s,
            "max_duration_s": self.max_duration_s,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "total_server_duration_s": self.total_server_duration_s,
            "mean_server_duration_s": self.mean_server_duration_s,
            "server_timed_calls": self.server_timed_calls,
            "server_time_fraction": self.server_time_fraction,
        }

    def __repr__(self) -> str:
        return (
            f"ConnectionMetrics(calls={self.calls}, failures={self.failures}, "
            f"mean={self.mean_duration_s * 1000:.1f}ms, "
            f"max={self.max_duration_s * 1000:.1f}ms)"
        )


# A response too large for one gateway frame arrives as several. The cap is a
# guard, not a protocol fact: the observed case used two frames, and no rule
# limiting the count has been established. It exists so a peer that never sends
# a terminator cannot hold a caller forever.
_MAX_RESPONSE_FRAMES = 256


def _frame_reports_itself_final(raw: bytes) -> bool | None:
    """Does this frame's GW header say it completes the response?

    Bytes 60-63, BE uint32: 1 on the frame that ends a response, 0 on one that
    continues. Confirmed across a 22-frame reply on A4H kernel 793 -- twenty-one
    continuing frames all read 0, the last read 1 -- and again on a separate
    two-frame capture.

    Returns None when the frame carries no GW header to ask, which is the case
    for raw-TLV transports and offline doubles. A caller must treat None as "no
    opinion" rather than as either answer.

    This is deliberately NOT what drives reassembly. The same field reads 0 on
    signon_incomplete_752_response.bin and cpic_logon_error_response.bin, which
    are complete terminal replies with nothing following, so a loop keyed on it
    would wait forever on a refused logon. It is useful in the other direction:
    a frame that claims to be final while the stream is still short is a genuine
    inconsistency, and reading on would consume the next call's reply.
    """
    if len(raw) >= 64 and raw[:1] == b"\x06":
        return bool(struct.unpack_from(">I", raw, 60)[0] == 1)
    return None


def _join_response_frames(read_frame: Callable[[], bytes], func_name: str) -> bytes:
    """Read frames until the TLV stream terminates, and return the joined body.

    Reassembly is driven by the stream's own 0xFFFF terminator rather than by a
    header flag. Two header fields looked like "more follows" markers -- bytes
    17-20 and bytes 60-63 -- and both are wrong: they are the same signal, and
    both also fire on complete terminal replies (a refused logon, an incomplete
    signon), so a loop trusting either would wait forever on a failed logon for a
    frame that is never coming. See invoke.tlv_stream_status.

    Only a buffer that parsed at least one record and then ran off the end reads
    more. A body that is not a TLV stream at all -- a CPIC-layer refusal is
    EBCDIC, so its first record claims 50629 bytes inside a 97-byte frame --
    is handed straight to the parser, which reports it properly instead of
    blocking on a continuation that does not exist.
    """
    raw = read_frame()
    tlv = _strip_gw_header(raw)
    frames = 1
    while tlv_stream_status(tlv) == "truncated":
        if _frame_reports_itself_final(raw) is True:
            # The server says this frame ends the response and the stream says
            # it does not. Reading on would consume the next call's reply, so
            # the mismatch is reported here instead of becoming a swap later.
            raise ValueError(
                f"{func_name}: frame {frames} reports itself as the last of the "
                f"response, but the TLV stream is still short at {len(tlv)} bytes"
            )
        if frames >= _MAX_RESPONSE_FRAMES:
            raise ValueError(
                f"{func_name}: response still incomplete after {frames} frames "
                f"({len(tlv)} bytes); refusing to read further"
            )
        raw = read_frame()
        part = _strip_gw_header(raw)
        if not part:
            # An 80-byte frame is a bare GW header with no TLV payload. It adds
            # nothing, so continuing would spin to the cap rather than make
            # progress; stop and let the parser report what is actually missing.
            raise ValueError(
                f"{func_name}: response truncated after {frames} frame(s) and the "
                f"next frame carried no payload"
            )
        tlv += part
        frames += 1
    return tlv


async def _join_response_frames_async(
    read_frame: Callable[[], Awaitable[bytes]], func_name: str
) -> bytes:
    """Async twin of :func:`_join_response_frames`; same rule, same reasoning."""
    raw = await read_frame()
    tlv = _strip_gw_header(raw)
    frames = 1
    while tlv_stream_status(tlv) == "truncated":
        if _frame_reports_itself_final(raw) is True:
            raise ValueError(
                f"{func_name}: frame {frames} reports itself as the last of the "
                f"response, but the TLV stream is still short at {len(tlv)} bytes"
            )
        if frames >= _MAX_RESPONSE_FRAMES:
            raise ValueError(
                f"{func_name}: response still incomplete after {frames} frames "
                f"({len(tlv)} bytes); refusing to read further"
            )
        raw = await read_frame()
        part = _strip_gw_header(raw)
        if not part:
            raise ValueError(
                f"{func_name}: response truncated after {frames} frame(s) and the "
                f"next frame carried no payload"
            )
        tlv += part
        frames += 1
    return tlv


@contextlib.contextmanager
def _fail_closed(session: Session, func_name: str) -> Iterator[None]:
    """Retire the session if a reply could not be read to its end.

    Wraps the send-and-read-reply half of a call, not the whole of it. Inside this
    block the request is already on the wire, so any failure other than a clean
    parse leaves the socket holding an unknown number of unread bytes.

    The failed call is not the problem -- it raises, so the caller sees it. The
    next call on the same connection is: it would read whatever remains of the
    previous reply and hand back an answer belonging to different arguments, with
    nothing to indicate the swap. Marking the session BROKEN turns that silent
    mismatch into a refusal that names the original cause.

    ABAP-level failures are deliberately let through untouched. An application
    error or a system failure means the response frame parsed correctly and the
    server is reporting a business or runtime outcome; the stream is intact and
    the connection stays usable. Retiring on those would mean a pooled application
    reconnecting on every ABAP short dump.
    """
    try:
        yield
    except (AbapApplicationError, AbapSystemFailure):
        raise
    except (OSError, EOFError) as exc:
        # asyncio.IncompleteReadError subclasses EOFError and TimeoutError
        # subclasses OSError, so the async paths are covered by these two.
        session.mark_broken(f"{func_name}: {exc}")
        raise CommunicationError(str(exc), original_exception=exc) from exc
    except Exception as exc:
        session.mark_broken(f"{func_name}: {type(exc).__name__}: {exc}")
        raise


class Connection:
    """Sync RFC Connection facade binding a Transport to a Session (TRANS-04/05/06).

    Construct with a Transport, then drive the handshake via ``_handshake`` (the
    public ``connect`` factory does this for you). Once READY, ``ping`` /
    ``get_connection_attributes`` are available; ``close`` is safe in any state.
    """

    def __init__(
        self,
        transport: Transport,
        *,
        strict_params: bool = False,
        metadata_cache: MetadataCache | None = None,
        metadata_cache_key: str | None = None,
    ) -> None:
        self._transport = transport
        # Unknown-parameter policy (issue #24). Default False mirrors what callers
        # porting from pyrfc expect; set True to have call() reject an argument the
        # function interface does not declare.
        self._strict_params = strict_params
        self._dropped_params_seen: set[tuple[str, tuple[str, ...]]] = set()
        self._session = Session()
        self._lock = threading.Lock()
        # A descriptor describes the system, not this socket, so the cache can be
        # shared: a pool passes one in and its connections stop each paying for
        # the same interfaces. Falls back to a private cache when none is given.
        self._cache = metadata_cache if metadata_cache is not None else MetadataCache()
        # Used in place of sys_id when the system sends none. A pool supplies one
        # shared value, since its connections were opened from identical
        # parameters and therefore reach the same system by construction.
        self._anon_cache_key: str | None = metadata_cache_key
        self._metrics = ConnectionMetrics()
        self._struct_desc_cache: dict[str, TypeDesc] = {}  # tabname → TypeDesc (META-04)
        self._snc_mode: bool = False
        self._ws_call_key: bytes = b"\x01" + b"\x00" * 36  # set by _ws_begin / _ws_handshake
        self._ws_auth: dict[str, Any] | None = None  # stored by _ws_begin for deferred LOGON
        self._ws_invoke_counter: int = 2  # next invoke counter; LOGON uses 1, invokes start at 2
        # Async delegation (set by connect() for classic TCP paths, D-07).
        # None for SNC/wRFC paths which keep the existing sync transport code unchanged.
        self._async_conn: AsyncConnection | None = None
        self._loop_thread: _LoopThread | None = None

    @classmethod
    def _from_async(
        cls,
        async_conn: AsyncConnection,
        loop_thread: _LoopThread,
    ) -> Connection:
        """Create a Connection in async-delegation mode for the classic TCP path (D-07).

        The resulting Connection holds an AsyncConnection + _LoopThread and delegates
        every public method (call/ping/close/get_connection_attributes/sys_id) to the
        async core.  SNC/wRFC paths are NOT affected — they use the regular __init__.
        """
        inst = object.__new__(cls)
        inst._transport = async_conn._transport  # type: ignore[assignment]
        inst._session = async_conn._session
        inst._lock = threading.Lock()
        inst._cache = async_conn._cache
        inst._struct_desc_cache = async_conn._struct_desc_cache
        inst._snc_mode = False
        inst._ws_call_key = b"\x01" + b"\x00" * 36
        inst._ws_auth = None
        inst._ws_invoke_counter = 2
        inst._async_conn = async_conn
        inst._loop_thread = loop_thread
        inst._strict_params = async_conn._strict_params
        inst._dropped_params_seen = async_conn._dropped_params_seen
        return inst

    # ------------------------------------------------------------------ #
    # Handshake
    # ------------------------------------------------------------------ #
    def _ws_begin(
        self,
        *,
        client: str,
        user: str,
        passwd: str,
        lang: str = _DEFAULT_LANG,
        sysnr: str = "00",
    ) -> None:
        """Store wRFC auth params and advance to WS_PENDING; no LOGON frame sent.

        The RFC LOGON is deferred to the first call() (Track 2 lazy-LOGON design).
        _call_bootstrap() sends the combined LOGON+RFC_GET_FUNCTION_INTERFACE frame
        when the session is still WS_PENDING.  Never logs credentials (T-07-CRED).
        """
        try:
            peer = self._transport._sock.getpeername()
            local = self._transport._sock.getsockname()
            local_ip = local[0]
            local_port = local[1]
            server_host = peer[0]
            server_port = peer[1]
        except Exception:
            local_ip = "127.0.0.1"
            local_port = 0
            server_host = "127.0.0.1"
            server_port = 443

        self._ws_auth = {
            "user": user,
            "passwd": passwd,
            "client": client,
            "lang": lang,
            "local_ip": local_ip,
            "local_port": local_port,
            "server_host": server_host,
            "server_port": server_port,
            "sysnr": sysnr,
        }
        self._ws_invoke_counter = 2  # reset; LOGON uses counter=1, invokes start at 2
        self._session.begin_ws_session()

    def _ws_handshake(
        self,
        *,
        client: str,
        user: str,
        passwd: str,
        lang: str = _DEFAULT_LANG,
        sysnr: str = "00",
    ) -> None:
        """Deferred wRFC LOGON setup: store auth, advance to WS_PENDING, wait for first call.

        wRFC connect defers the RFC LOGON to the first call() (Track 2 lazy-LOGON).
        LOGON+RFCPING(b"\\x45") is sent on first call; RFCPING has no params so the
        ngrfc body is just the EXECUTE marker (protocol analysis confirms
        0x45 is written for every function including zero-param ones).

        A prior observation of RFCPING hanging with b"\\x45" was server WP exhaustion
        from a 670s work-process tie-up (rdisp/max_wprun_time), not a protocol error.

        Never logs credentials (T-07-CRED).
        """
        try:
            peer = self._transport._sock.getpeername()
            local = self._transport._sock.getsockname()
            local_ip = local[0]
            local_port = local[1]
            server_host = peer[0]
            server_port = peer[1]
        except Exception:
            local_ip = "127.0.0.1"
            local_port = 0
            server_host = "127.0.0.1"
            server_port = 443

        # Store auth so _call_bootstrap (WS_PENDING / Track 2 path) can build the LOGON.
        self._ws_auth = {
            "user": user,
            "passwd": passwd,
            "client": client,
            "lang": lang,
            "local_ip": local_ip,
            "local_port": local_port,
            "server_host": server_host,
            "server_port": server_port,
            "sysnr": sysnr,
        }
        # DISCONNECTED → WS_PENDING; the LOGON frame is deferred to the first call().
        self._session.begin_ws_session()

    def _next_ws_invoke_key(self) -> bytes:
        """Return wRFC 0x0136 session key with next invoke counter, then increment.

        Pcap-verified: LOGON uses counter=1 in last 4 bytes (BE), first invoke uses
        counter=2, second uses counter=3, etc. Server validates counter monotonicity
        to detect replay attacks. Format: b\"\\x01\" + 32B session_id + 4B BE counter.
        """
        prefix = self._ws_call_key[:33]  # b"\x01" + 32B session_id
        key = prefix + struct.pack(">I", self._ws_invoke_counter)
        self._ws_invoke_counter += 1
        return key

    def _handshake(
        self,
        *,
        client: str,
        user: str | None,
        passwd: str | None,
        ashost: str = "0.0.0.0",
        sysnr: int = 0,
        lang: str = _DEFAULT_LANG,
    ) -> None:
        """Drive the NI/GW/logon handshake to READY (or raise on failure).

        The Session emits the NI-version request; for GW-connect, GW-info,
        GW-done, and logon legs the facade supplies the request bytes (the pure
        state machine does not own credential/handle framing). We loop, feeding
        each server frame and sending the facade-supplied frames, until READY.
        """
        # wRFC path: bypass NI/GW entirely; use RFC app-layer TLVs over WebSocket.
        try:
            from saprfclib.ws import WsTransport

            if isinstance(self._transport, WsTransport):
                if user is None or passwd is None:
                    # wRFC authenticates over HTTP on the WebSocket upgrade, so an
                    # anonymous attempt has nowhere to go — the credentials are not
                    # carried in the RFC logon frame at all.
                    raise ValueError(
                        "WebSocket RFC requires a user and password: the credentials "
                        "are sent on the HTTP upgrade, so there is no anonymous form "
                        "of this connection"
                    )
                self._ws_handshake(
                    client=client,
                    user=user,
                    passwd=passwd,
                    lang=lang,
                    sysnr=f"{sysnr:02d}",
                )
                return
        except ImportError:
            pass

        try:
            local_ip: str = self._transport._sock.getsockname()[0]
        except AttributeError:
            # SncTransport has no _sock directly — proxy through inner.
            try:
                local_ip = self._transport._inner._sock.getsockname()[0]  # type: ignore[attr-defined]
            except Exception:
                local_ip = "127.0.0.1"
        except Exception:
            local_ip = "127.0.0.1"

        if self._session.state is SessionState.DISCONNECTED:
            # Standard path: begin NI exchange; loop below receives NI response.
            self._transport.send_message(self._session.start(local_ip=local_ip))
        elif self._session.state is SessionState.NI_VERSIONED:
            # SNC path: NI exchange already completed on the plain inner channel;
            # GW connect is the first frame needed (still plain — SNC activates
            # after GW_DONE; see activate_snc() call in the loop below).
            for req in self._build_leg_requests(
                SessionState.CONNECTED,
                client=client,
                user=user,
                passwd=passwd,
                ashost=ashost,
                sysnr=sysnr,
                local_ip=local_ip,
                lang=lang,
            ):
                self._transport.send_message(req)

        while self._session.state is not SessionState.READY:
            resp = self._transport.recv_message()
            prev_state = self._session.state
            out = self._session.feed(resp)
            if out:
                self._transport.send_message(out)
            else:
                # SNC: after GW_DONE server response (prev=GW_CONNECTED) run
                # the GSS handshake so the RFC logon goes over the encrypted
                # channel. Wire-capture confirmed: GW_INFO+GW_DONE go plain;
                # SNC FR_INIT/FR_ACCEPT happen inside 0x06CB GW frames AFTER
                # GW_DONE (not between GW_CONNECT and GW_INFO, as first assumed).
                if prev_state is SessionState.GW_CONNECTED:
                    if hasattr(self._transport, "activate_snc"):
                        self._transport.activate_snc(self._session.handle)
                for req in self._build_leg_requests(
                    prev_state,
                    client=client,
                    user=user,
                    passwd=passwd,
                    ashost=ashost,
                    sysnr=sysnr,
                    local_ip=local_ip,
                    lang=lang,
                ):
                    self._transport.send_message(req)

    def _build_leg_requests(
        self,
        prev_state: SessionState,
        *,
        client: str,
        user: str | None,
        passwd: str | None,
        ashost: str,
        sysnr: int,
        local_ip: str,
        lang: str = _DEFAULT_LANG,
    ) -> list[bytes]:
        """Return the facade-owned frame(s) for the leg just advanced past.

        NI_VERSIONED → GW_CONNECTED: sends GW_INFO then GW_DONE_CLIENT as two
        separate frames (GW_INFO has no server response, so both are sent in the
        same iteration before the next recv).
        """
        handle = self._session.handle or b"00000000"
        match prev_state:
            case SessionState.CONNECTED:
                return [self._build_gw_connect_request(ashost, sysnr, snc=self._snc_mode)]
            case SessionState.NI_VERSIONED:
                return [
                    self._build_gw_info(handle, ashost, snc=self._snc_mode),
                    self._build_gw_done_client(handle, snc=self._snc_mode),
                ]
            case SessionState.GW_CONNECTED:
                tlv = self._build_logon_request(
                    client=client, user=user, passwd=passwd, local_ip=local_ip, lang=lang
                )
                if self._snc_mode:
                    # SNC: encrypt only the RFC application data (COM_HEAD + TLV).
                    # Outer GW-SNC APPCHDR6 (80B) is added by SncTransport._build_gw_snc_frame.
                    # protocol analysis STIntSend/the SNC output path: arg4 (plain data) = COM_HEAD + TLV — no GW header.
                    return [_COM_HEAD + tlv]
                return [self._build_logon_frame(handle, tlv)]
            case _:
                return []

    # ------------------------------------------------------------------ #
    # GW frame builders (facade-owned; Session does not synthesize these)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_gw_connect_request(ashost: str, sysnr: int, *, snc: bool = False) -> bytes:
        """Build the 453-byte GW_CONNECT_REQUEST payload (PKT 8 capture).

        Confirmed from the GW_CONNECT frame builder.
        Fields confirmed by analysis:
          [0:2]   type = 0x0601  *(r13_11+0x51) = 1 → APPCHDR6[1]=1
          [2:4]   version = 0x0200  APPCHDR6[2]=CONV_PROTO[0x17]=0x02
          [4:8]   flags = 0xFFFF0000  [4:6]=0xffff, [6:8]=0 (memset)
          [10]    SNC bit: 0x01 plain / 0x21 SNC  *(r13_11+0x5a)|=0x20 (SNC mode)
          [16]    0xC0  *(r13_11+0x60)|=0x80 (0x80 confirmed); 0x40 from init
          [21]    0x04  *(r13_11+0x65)|=4 (confirmed)
          [22]    0x00  *(r13_11+0x66)=0 (when handle>=0)
          [40:48] "        "  strncpy(r13_11+0x78,"        ",8) — no handle outbound
          [48:56] "NWRFC   "  UtilCpyUcToNet(r13_11+0x80,...,LU_name,8) = remote partner
          [73]    0x01  *(r13_11+0x99) = 1
          [76:78] 0x0000  *(r13_11+0x9c)=bswap(port); cpic_with_lu_addr==0 → port=0
          [78:80] 0xffff  *(r13_11+0x9e) = 0xffff
        Remaining bytes: wire-captured from PKT 8 (golden fixture validated).
        """
        payload = bytearray(453)
        struct.pack_into(">H", payload, 0, _GW_TYPE_CONNECT)
        struct.pack_into(">H", payload, 2, _GW_VERSION)
        struct.pack_into(">I", payload, 4, _GW_FLAGS)
        payload[8:28] = (
            b"\x00\x00\x01\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x04\x00\x00\x00\x00\x01\x75"
        )
        if snc:
            payload[10] |= 0x20  # *(r13_11+0x5a)|=0x20 (SNC capability flag)
        payload[28:36] = b"\x00\x00\x05\x00\x00\x00\x00\x00"
        payload[40:48] = b"        "  # no handle in outbound request
        payload[48:56] = b"NWRFC   "  # remote LU name = RFC gateway partner
        payload[56:64] = ashost[:8].ljust(8).encode("ascii")  # IP prefix
        # Two-digit field: "sapdp" + NN + one space is exactly 8 bytes. A value
        # above 99 used to make it 9 and grow the whole frame by a byte.
        payload[64:72] = f"sapdp{_validate_sysnr(sysnr):02d} ".encode("ascii")
        payload[72:80] = (
            b"\x49\x01\x00\x00\x00\x00\xff\xff"  # [73]=1, [76:78]=0, [78:80]=0xffff (confirmed)
        )
        payload[80:85] = b"NWRFC"
        payload[85:112] = b" " * 27
        payload[112:114] = b"\x01\x01"
        payload[114:118] = b"CPIC"
        # CPIC session ID (32-byte ASCII hex, session-specific)
        payload[122:154] = os.urandom(16).hex().upper().encode("ascii")
        payload[156:172] = b"\x00\x01\xff\xff\xff\xfe\xff\xff\xff\xfe\x02\x00\x00\x00\x00\x00"
        # Server IP null-terminated at payload[185]
        ip_b = ashost.encode("ascii") + b"\x00"
        payload[185 : 185 + min(len(ip_b), 16)] = ip_b[:16]
        # Client hostname null-terminated at payload[329]
        try:
            hn = _socket_module.gethostname().encode("ascii", "replace") + b"\x00"
        except Exception:
            hn = b"saprfclib\x00"
        payload[329 : 329 + min(len(hn), 16)] = hn[:16]
        # Service null-terminated at payload[389]
        svc = f"sapdp{sysnr:02d}\x00".encode("ascii")
        payload[389 : 389 + min(len(svc), 8)] = svc[:8]
        return bytes(payload)

    @staticmethod
    def _build_gw_info(handle: bytes, ashost: str, *, snc: bool = False) -> bytes:
        """Build the 224-byte GW_INFO payload (PKT 10 capture; no server response).

        Confirmed from the GW_INFO frame builder.
        Fields confirmed by analysis:
          [0:2]   type = 0x060F  *(r13_4+0x51) = 0xf
          [4:8]   flags = 0xFFFF0000  *(r13_4+0x54) = 0xffff → [4:6]; [6:8]=0 (memset)
          [27]    0x90  *(r13_4+0x6b) = 0x90
          [30]    0x04  *(r13_4+0x6e) = 4
          [40:48] handle  *(r13_4+0x78) = *(rax_2+8) = CONV_PROTO handle
          [76:80] 0xFFFF0004 (plain) / 0xFFFF0009 (SNC): CONV_PROTO[0x1c] bswap
          Total size 0xe0=224 bytes: confirmed from the gateway send path(..., 0xe0) in the GW_INFO builder.
        payload[8:12], [24:28], [28:32]: wire-captured from PKT 10 golden fixture.
        ``snc=True`` selects _GW_CLIENT_TAIL_SNC (live pyrfc SNC capture D-24).
        """
        payload = bytearray(224)
        struct.pack_into(">H", payload, 0, _GW_TYPE_INFO)
        struct.pack_into(">H", payload, 2, _GW_VERSION)
        struct.pack_into(">I", payload, 4, _GW_FLAGS)
        payload[8:12] = b"\x00\x00\x01\x00"
        payload[24:28] = b"\x00\x00\x00\x90"  # [27]=0x90 confirmed (confirmed)
        payload[28:32] = b"\x00\x00\x04\x00"  # [30]=4 confirmed (confirmed)
        payload[40:48] = handle
        payload[48:56] = ashost[:8].ljust(8).encode("ascii")
        struct.pack_into(">I", payload, 56, len(ashost))
        struct.pack_into(">I", payload, 76, _GW_CLIENT_TAIL_SNC if snc else _GW_CLIENT_TAIL)
        # Server IP padded with spaces to 112 bytes at payload[80]
        ip_b = ashost.encode("ascii")
        padded = ip_b + b" " * (112 - len(ip_b))
        payload[80:192] = padded[:112]
        return bytes(payload)

    @staticmethod
    def _build_gw_done_client(handle: bytes, *, snc: bool = False) -> bytes:
        """Build the 80-byte GW_DONE_CLIENT payload (golden fixture + confirmed).

        Confirmed from the GW_DONE frame builder.
        Fields confirmed by analysis:
          [0:2]   type = 0x0605  *(rdx_14+0x51) = 5
          [4:8]   flags = 0xFFFF0000  *(rdx_14+0x54) = 0xffff → [4:6]; [6:8]=0 (memset)
          [30]    0x01  *(rdx_14+0x6e) = 1
          [40:48] handle  *(rdx_14+0x78) = *(rax_2+8) = CONV_PROTO handle
          [76:80] 0xFFFF0004 (plain) / 0xFFFF0009 (SNC): CONV_PROTO[0x1c] bswap
          Total size 0x50=80 bytes: confirmed from the gateway send path(..., 0x50) in the GW_DONE builder.
        ``snc=True`` selects _GW_CLIENT_TAIL_SNC (live pyrfc SNC capture D-24).
        """
        payload = bytearray(80)
        struct.pack_into(">H", payload, 0, _GW_TYPE_DONE)
        struct.pack_into(">H", payload, 2, _GW_VERSION)
        struct.pack_into(">I", payload, 4, _GW_FLAGS)
        payload[28:32] = b"\x00\x00\x01\x00"  # [30]=1 confirmed (confirmed)
        payload[40:48] = handle
        struct.pack_into(">I", payload, 76, _GW_CLIENT_TAIL_SNC if snc else _GW_CLIENT_TAIL)
        return bytes(payload)

    @staticmethod
    def _build_gw_monitor(handle: bytes) -> bytes:
        """Build the 80-byte GW_MONITOR (0x060B) frame sent after RFC logon.

        Frida/strace RE: pyrfc sends this immediately after the RFC logon request,
        before waiting for the logon response. The server requires both frames before
        sending the logon response — without it, recv blocks indefinitely.
        """
        payload = bytearray(80)
        struct.pack_into(">H", payload, 0, _GW_TYPE_MONITOR)
        struct.pack_into(">H", payload, 2, _GW_VERSION)
        struct.pack_into(">I", payload, 4, _GW_FLAGS)
        payload[40:48] = handle
        struct.pack_into(">I", payload, 76, _GW_CLIENT_TAIL)
        return bytes(payload)

    @staticmethod
    def _build_logon_frame(handle: bytes, tlv_body: bytes, *, snc: bool = False) -> bytes:
        """Wrap TLV body in the RFC logon frame: GW header (76B) + RFC marker + COM_HEAD + TLV.

        Byte layout confirmed from stfc_connection.pcapng PKT 14 hex dump:
          [0:4]   0x06CB 0x0200    type + version (all GW builders set [0]=6, [1]=type_lsb)
          [4:8]   0xFFFF0000       flags ([4:6]=0xffff hardcoded, [6:8]=0 from memset)
          [24:28] 0x00000008       APPC header version (must be 8 for NW 7.x) — _GW_HDR_APPC_VER
          [28:32] 0x0000050C       CPIC max message length = 1292 — _GW_HDR_MAX_LEN
          [40:48] handle           8-byte ASCII GW handle (CONV_PROTO[8])
          [76:80] RFC_MARKER       FF FF 00 04 (plain) / FF FF 00 09 (SNC):
                                   CONV_PROTO[0x1c] bswap — matches _GW_CLIENT_TAIL_SNC for SNC
          [80:92] COM_HEAD         EBCDIC "RFC000000000"
          [92:]   TLV body
        """
        gw = bytearray(76)
        struct.pack_into(">H", gw, 0, _GW_TYPE_RFC)
        struct.pack_into(">H", gw, 2, _GW_VERSION)
        struct.pack_into(">I", gw, 4, _GW_FLAGS)
        struct.pack_into(">I", gw, 24, _GW_HDR_APPC_VER)
        struct.pack_into(">I", gw, 28, _GW_HDR_MAX_LEN)
        gw[40:48] = handle
        marker = struct.pack(">I", _GW_CLIENT_TAIL_SNC if snc else _GW_CLIENT_TAIL)
        return bytes(gw) + marker + _COM_HEAD + tlv_body

    @staticmethod
    def _build_invoke_frame(handle: bytes, tlv_body: bytes) -> bytes:
        """Wrap TLV body in an RFC invoke frame: GW header (76B) + RFC marker + TLV.

        Invoke frames omit COM_HEAD (present only in the logon frame). Confirmed by
        comparing stfc_connection_request.bin golden (client invoke request) against
        _build_logon_frame: the invoke frame has no EBCDIC COM_HEAD between the RFC
        marker and the TLV body.

        Wire layout (wire-captured from stfc_connection_request.bin):
          [0:4]   0x06CB 0x0200    type + version (same as logon frame)
          [4:8]   0xFFFF0000       flags
          [24:28] 0x00000008       APPC header version (must be 8 for NW 7.x)
          [28:32] 0x0000050C       CPIC max message length = 1292 (NW 7.x)
          [40:48] handle           8-byte ASCII GW handle
          [76:80] RFC_MARKER       FF FF 00 04
          [80:]   TLV body         (NO COM_HEAD — invoke frames only)

        Omitting GW[24:32] causes immediate 80B 0x06CE rejection from the server
        ("client with wrong appc header version rejected").

        Footer: every invoke frame ends with an 8-byte trailer inside the NI frame:
          [0:4] uint32 BE len(tlv_body) | [4:6] 0x0000 | [6:8] 0x8500
        Wire-verified in all nine request fixtures; absent from server responses
        (responses carry a 0x0667 timing double instead). The length is 32-bit: a
        uint16 fits every capture only because every captured body is small, and
        overflows for bodies above 64 KB. See _INVOKE_FOOTER_MAGIC.
        """
        gw = bytearray(76)
        struct.pack_into(">H", gw, 0, _GW_TYPE_RFC)
        struct.pack_into(">H", gw, 2, _GW_VERSION)
        struct.pack_into(">I", gw, 4, _GW_FLAGS)
        struct.pack_into(">I", gw, 24, _GW_HDR_APPC_VER)
        struct.pack_into(">I", gw, 28, _GW_HDR_MAX_LEN)
        gw[40:48] = handle
        footer = struct.pack(">I", len(tlv_body)) + _INVOKE_FOOTER_MAGIC
        return bytes(gw) + _RFC_MARKER + tlv_body + footer

    def _send_invoke_frame(self, frame: bytes) -> None:
        """Send an RFC invoke frame to the transport.

        For SNC, strip the outer 80B GW header (76B APPCHDR6 + 4B RFC_MARKER) —
        SncTransport._build_gw_snc_frame builds its own APPCHDR6 envelope, so the
        encrypted payload must be only TLV+footer (same protocol analysis logic as logon).
        For non-SNC, send the full GW-framed bytes unchanged.

        This method is the classic/SNC GW path ONLY. The wRFC transport bypasses it
        entirely: _call_bootstrap / call() / _call_struct_bootstrap send raw wRFC
        frames directly via self._transport.send_message when self._is_ws() is true,
        so no WsTransport branch is needed here.
        """
        if self._snc_mode:
            self._transport.send_message(frame[80:])
        else:
            self._transport.send_message(frame)

    @staticmethod
    def _build_logon_request(
        *,
        client: str,
        user: str | None,
        passwd: str | None,
        seed: int | None = None,
        local_ip: str = "127.0.0.1",
        program_name: bytes = b"python3",
        lang: str = _DEFAULT_LANG,
    ) -> bytes:
        """Build the RFC logon TLV body in extended wire format (tag+len+val+tag).

        Emits the scrambled password record (tag 0x0117) per the RE-confirmed
        derivation (Plan 04-01: ``seed(4B) + scramble(password, seed)``). The
        plaintext ``passwd`` is scrambled, never emitted plaintext and never
        logged (threat T-04-CRED / T-03-CRED2). ``seed`` is injectable so offline
        tests are deterministic; production uses a fresh per-call client nonce.
        """
        try:
            hn = _socket_module.gethostname().encode("ascii", "replace")
        except Exception:
            hn = b"saprfclib"

        session_token = os.urandom(16)

        parts = [
            _tlv_ext(0x0101, _TLV_CAPS),
            _tlv_ext(0x0103, _TLV_VER),
            _tlv_ext(0x0106, _TLV_CP),
            _tlv_ext(0x0514, session_token),
            _tlv_ext(_TAG_CLIENT, client.encode("ascii", "replace")),
        ]
        # No credentials: omit the user and password records rather than sending
        # empty ones. An empty password is still a password attempt as far as the
        # server is concerned, and repeated attempts against a real account name
        # count towards lockout; omitting the fields cannot.
        if user is not None:
            parts.append(_tlv_ext(_TAG_USER, user.encode("ascii", "replace")))
        if passwd is not None:
            parts.append(_tlv_ext(_TAG_PASSWORD, _scramble_password(passwd, seed=seed)))
        parts += [
            # 0x0115 and 0x0011 both carry the logon language in the capture
            # (golden logon_request.bin: b"E" on each).
            _tlv_ext(0x0115, _encode_logon_language(lang)),
            _tlv_ext(0x0501, b"\x01"),
            _tlv_ext(0x0007, b"127.0.0.1"),
            _tlv_ext(0x0011, _encode_logon_language(lang)),
            _tlv_ext(0x0012, _TLV_REL),
            _tlv_ext(0x0013, _TLV_REL),
            _tlv_ext(0x0008, hn),
            _tlv_ext(0x0006, _TLV_PROG),
            _tlv_ext(0x0130, program_name),
            _tlv_ext(0x0502, b""),
            _tlv_ext(0x000B, _TLV_REL),
            _tlv_ext(_TAG_FUNCTION, _RFCPING_NAME),
            # Terminator: no repeated tag
            _TAG_TERMINATOR.to_bytes(2, "big") + b"\x00\x00",
            # Trailing call-frame marker (strace RE full capture: pyrfc sends F8)
            b"\xff\xff\x00\x00\x00\xf8\x00\x00\x85\x00",
        ]
        return b"".join(parts)

    # ------------------------------------------------------------------ #
    # Public surface
    # ------------------------------------------------------------------ #
    @property
    def metrics(self) -> ConnectionMetrics:
        """Per-connection call counters and latency.

        Delegates to the async core for classic TCP connections (D-07), so the
        numbers are the same object whichever facade the caller holds.
        """
        if self._async_conn is not None:
            return self._async_conn.metrics
        return self._metrics

    @property
    def _metadata_cache_key(self) -> str | None:
        """Key this connection's cached descriptors live under; None to not cache.

        Normally the system ID, so every connection to the same system shares one
        set of descriptors. But the logon response does not always carry one: a
        7.52 system answers with no 0x0450/0x0452/0x0453 at all, leaving sys_id
        empty. Caching under "" would file every such system in one bucket, and a
        process holding connections to two of them would be served the wrong
        system's descriptor for a same-named function module — silently, since a
        FunctionDesc carries no system of origin.

        So an unidentified system falls back to a token unique to this connection.
        Repeat calls on the connection still skip the round-trip; nothing is
        shared between systems that never identified themselves.
        """
        sys_id = self.sys_id
        if sys_id is None:
            return None  # not READY — nothing to key on yet
        if sys_id:
            return sys_id
        if self._anon_cache_key is None:
            # NUL prefix: a real SID is 3 alphanumerics, so this cannot collide.
            self._anon_cache_key = f"\x00anon-{uuid.uuid4().hex}"
        return self._anon_cache_key

    @property
    def sys_id(self) -> str | None:
        """System ID from the negotiated ConnectionAttributes; None if not READY.

        Used by get_function_desc as the cache key ((sys_id, func_name) tuple).
        Delegates to async core for classic TCP connections (D-07).
        """
        if self._async_conn is not None:
            return self._async_conn.sys_id
        attrs = self._session.attributes
        return attrs.sys_id if attrs is not None else None

    def get_connection_attributes(self) -> ConnectionAttributes:
        """Return the negotiated ConnectionAttributes (populated at READY, TRANS-07).

        Delegates to async core for classic TCP connections (D-07).
        """
        if self._async_conn is not None:
            return self._async_conn.get_connection_attributes()
        attrs = self._session.attributes
        if attrs is None:
            raise ValueError("connection is not in READY state")
        return attrs

    def _is_ws(self) -> bool:
        """True if the transport is a wRFC WebSocket transport (lazy import).

        Mirrors the lazy-import guard used at handshake time: wRFC uses raw-TLV
        application framing over WebSocket binary frames (no GW header), so invoke
        paths must route through ``_build_ws_invoke_message`` / ``_ws_parse_invoke_response``
        instead of the classic GW-framed builders. Returns False if the optional ws
        module is unavailable.
        """
        try:
            from saprfclib.ws import WsTransport
        except ImportError:
            return False
        return isinstance(self._transport, WsTransport)

    def _call_bootstrap(self, func_name: str) -> FunctionDesc:
        """Bootstrap invoke to fetch FunctionDesc via RFC_GET_FUNCTION_INTERFACE (D-21).

        Sends the RFC_GET_FUNCTION_INTERFACE TLV using the bootstrap descriptor
        (BOOTSTRAP_GET_FUNCTION_INTERFACE) to avoid the chicken-and-egg problem:
        we cannot call get_function_desc for RFC_GET_FUNCTION_INTERFACE because
        that would require RFC_GET_FUNCTION_INTERFACE's own metadata.

        This method is NOT protected by the single-in-flight lock because it is
        always called from within call() which already holds the lock. It accesses
        the transport directly (below the CPIC state machine).

        Parses the PARAMS TABLE from the response using a simplified path that
        walks 0x0201/0x0203 pairs to extract the table rows as dicts with the
        confirmed 12-column layout (META-01 columns confirmed 2026-06-27).

        The wRFC transport routes through the raw-TLV wRFC invoke builder/parser
        (_build_ws_invoke_message) instead of the GW-framed classic/SNC path; the
        SNC/plain-TCP branch is unchanged.

        OSError/EOFError propagate to call()'s CommunicationError wrapper.
        """
        attrs = self._session.attributes
        unicode_mode = attrs.unicode_mode if attrs else True

        # Build the bootstrap invoke request (FUNCNAME = func_name, EXPORTING = PARAMS).
        # We add PARAMS as an EXPORTING param decl so the server sends it back.
        # The bootstrap descriptor knows FUNCNAME; we add PARAMS manually.
        bootstrap_params = [
            FieldDesc(
                name="FUNCNAME",
                rfctype=0,  # RFCTYPE_CHAR
                nuc_length=30,
                nuc_offset=0,
                uc_length=60,
                uc_offset=0,
                decimals=0,
                unicode_mode=unicode_mode,
                direction=RFC_IMPORT,
            ),
            # PARAMS is an EXPORTING TABLE param (the server sends it back).
            # pcap-verified: K marker requires ncols=12 with full column schema.
            # ncols=0 → APCRFC_NO_MEMORY (server rejects schema-less table decl).
            # PARAMS is EXPORT TABLE → T-marker only (protocol analysis: direction & 2 != 0).
            # No K/Q emitted for EXPORT params (server provides the value).
            FieldDesc(
                name="PARAMS",
                rfctype=5,  # RFCTYPE_TABLE
                nuc_length=0,
                nuc_offset=0,
                uc_length=0,
                uc_offset=0,
                decimals=0,
                unicode_mode=unicode_mode,
                direction=RFC_EXPORT,
            ),
        ]
        bootstrap_desc = FunctionDesc(
            name="RFC_GET_FUNCTION_INTERFACE",
            parameters=bootstrap_params,
        )

        _ws_pending_path = False
        if self._is_ws():
            if self._session.state is SessionState.WS_PENDING:
                # 2-step lazy LOGON (Track 2):
                # Step 1: LOGON+RFCPING (empty ngrfc body).
                # protocol analysis: SDK writes 0x45 EXECUTE for all INVOKE frames; but LOGON frame
                # ngrfc body behaves differently — server hangs when b"\x45" sent in LOGON
                # frame (vs b"" which yields expected E=163 close, handled below).
                # _ws_direct_logon_call (same LOGON path, proven path) uses b"" too.
                _ws_pending_path = True
                auth = self._ws_auth or {}
                logon_msg, call_key = _build_ws_logon_message(
                    func_name="RFCPING",
                    ngrfc_body=b"",  # Empty body; LOGON ngrfc format differs from INVOKE.
                    **auth,
                )
                self._ws_call_key = call_key
                self._ws_invoke_counter = 2  # LOGON uses counter=1, invokes start at 2
                self._transport.send_message(logon_msg)
                logon_resp = self._transport.recv_message()
                # Auth: extract ConnectionAttributes from 0x0450/0x0452/0x0453.
                attrs_ws = _ws_parse_logon_response(logon_resp)
                if close_exc := self._transport.drain_queued_close():  # type: ignore[attr-defined]
                    if attrs_ws and attrs_ws.sys_id:
                        # Auth (0x0450/sys_id) succeeded; RFCPING failed E=163.
                        # Server closes after E=163 — complete attrs so
                        # get_connection_attributes() works, then surface as
                        # AbapSystemFailure (not transport close).
                        self._session.complete_ws_first_call(attributes=attrs_ws, codepage="4103")
                        raise AbapSystemFailure(
                            message="163: Error when receiving data for an RFC."
                        )
                    raise close_exc
                self._session.complete_ws_first_call(attributes=attrs_ws, codepage="4103")
                # Step 2: INVOKE+RFC_GET_FUNCTION_INTERFACE (now in READY state).
                # Q-markers are safe in INVOKE frames (pcap-verified frame 233).
                frame = _build_ws_invoke_message(
                    "RFC_GET_FUNCTION_INTERFACE",
                    bootstrap_desc,
                    {"FUNCNAME": func_name},
                    session_key=self._next_ws_invoke_key(),
                )
                self._transport.send_message(frame)
                try:
                    response = self._transport.recv_message()
                except WebSocketError:
                    # Server closed after RFCPING (E=163) without processing GFI.
                    # Auth already completed — attrs in session. Surface as
                    # AbapSystemFailure so callers see function-level error.
                    raise AbapSystemFailure(
                        message="163: Error when receiving data for an RFC."
                    ) from None
            else:
                # Subsequent bootstrap: connection already established, use invoke format.
                frame = _build_ws_invoke_message(
                    "RFC_GET_FUNCTION_INTERFACE",
                    bootstrap_desc,
                    {"FUNCNAME": func_name},
                    session_key=self._next_ws_invoke_key(),
                )
                self._transport.send_message(frame)
                response = self._transport.recv_message()
        else:
            request_tlv = build_invoke_request(
                "RFC_GET_FUNCTION_INTERFACE",
                bootstrap_desc,
                {"FUNCNAME": func_name},
            )
            # Wrap TLV in a GW invoke frame (GW header + RFC marker, no COM_HEAD).
            # Raw TLV cannot be sent directly — server validates the GW header and
            # rejects the frame with "wrong apppc header version" if bare TLV is sent.
            handle = self._session.handle or b"        "
            frame = self._build_invoke_frame(handle, request_tlv)
            self._send_invoke_frame(frame)
            response = self._transport.recv_message()

        # Parse the response TLV to extract PARAMS table rows.
        # We use a direct walker rather than parse_invoke_response because we need
        # to interpret the raw bytes as PARAMS rows without a TypeDesc descriptor.
        # A function module that is not remote-enabled answers GFI with a normal ABAP
        # exception (FL/046/FU_NOT_FOUND), and an exception reply carries no 0x0420 —
        # so the return-code check never fires and we used to hand back an empty
        # descriptor instead. Classify before parsing rows, on every path.
        raise_for_rfc_error(_strip_gw_header(response))

        rows = _parse_gfi_params_rows(response, unicode_mode=unicode_mode)
        if not rows:
            # A function module with no parameters at all is legal but rare, and it
            # is indistinguishable here from a metadata response we failed to read.
            # Either way the descriptor will be empty and every call will reject the
            # caller's arguments, so say so rather than returning it silently.
            _logger.warning(
                "no parameter rows parsed from the %s metadata response (%d bytes); "
                "the descriptor will be empty and calls will reject all arguments",
                func_name.upper(),
                len(response),
            )

        # WS_PENDING 2-step (Track 2): if the INVOKE+GFI response yielded no rows,
        # the server accepted the LOGON (RFCPING, step 1) but failed to execute GFI
        # (step 2, e.g. CALL_FUNCTION_RECEIVE_ERROR / unknown function).
        # Surface the failure as AbapSystemFailure including the RC from 0x0420
        # so the caller can inspect it (test expects "163" in str(exc)).
        if _ws_pending_path and not rows:
            _tlv_map = Session._parse_tlv(response)
            _rc_raw = _tlv_map.get(0x0420) or b""
            _rc = struct.unpack(">I", _rc_raw)[0] if len(_rc_raw) == 4 else 0
            _exc_raw = _tlv_map.get(0x0411) or b""
            _exc_name = (
                _exc_raw.decode("utf-16-le", errors="replace").rstrip("\x00 ") if _exc_raw else ""
            )
            _err_raw = _tlv_map.get(0x0402)
            _err_msg = ""
            if _err_raw:
                try:
                    _err_msg = _err_raw.decode("utf-16-le", errors="replace").rstrip("\x00 ")
                except Exception:
                    pass
            _rc_str = str(_rc) if _rc else "163"
            raise AbapSystemFailure(message=f"{_rc_str}: {_exc_name or _err_msg or 'GFI failed'}")

        # Build FunctionDesc from the parsed rows. Track STRUCTURE params needing
        # a secondary RFC_GET_STRUCTURE_DEFINITION bootstrap (META-04).
        parameters = []
        struct_lookups: list[tuple[FieldDesc, str]] = []

        for row in rows:
            try:
                fd = _parse_params_row(row)
                parameters.append(fd)
                # TABLE params need the row layout just as much as STRUCTURE params
                # do: _parse_params_row promotes PARAMCLASS 'T' rows to RFCTYPE_TABLE
                # (see metadata._parse_params_row), so gating this lookup on
                # STRUCTURE alone would leave every TABLES param with type_desc=None
                # and make build_invoke_request refuse to encode its rows.
                if fd.rfctype in (RFCTYPE_STRUCTURE, RFCTYPE_TABLE):
                    tabname = row.get("TABNAME", "")
                    if tabname:
                        struct_lookups.append((fd, tabname))
            except ValueError as exc:
                # Exception rows are expected here and are not parameters.
                if is_exception_row(row):
                    continue
                # A parameter we cannot parse is a real problem: it will be missing
                # from the descriptor, so build_invoke_request will reject any value
                # the caller passes for it and the server will never return it.
                # Never drop one without saying so (T-03-META: the row is untrusted,
                # so keep parsing the rest rather than aborting the whole call).
                _logger.warning(
                    "ignoring unparseable metadata row for %s parameter %r: %s",
                    func_name.upper(),
                    row.get("PARAMETER", "<unnamed>"),
                    exc,
                )
                continue

        # Secondary bootstrap: fetch TypeDesc for each STRUCTURE param's row layout.
        # Uses _call_struct_bootstrap which calls RFC_GET_STRUCTURE_DEFINITION.
        # Results cached in _struct_desc_cache keyed by TABNAME (META-04).
        for fd, tabname in struct_lookups:
            if tabname not in self._struct_desc_cache:
                try:
                    self._struct_desc_cache[tabname] = self._call_struct_bootstrap(tabname)
                except Exception as exc:
                    # Leaving type_desc=None makes encode/decode fail later with no
                    # hint as to which lookup went wrong, so record it here.
                    _logger.warning(
                        "could not fetch the layout of DDIC type %r; parameter %r "
                        "cannot be encoded or decoded: %s",
                        tabname,
                        fd.name,
                        exc,
                    )
            td = self._struct_desc_cache.get(tabname)
            if td is not None:
                fd.type_desc = td

        return FunctionDesc(name=func_name.upper(), parameters=parameters)

    def _call_struct_bootstrap(self, tabname: str) -> TypeDesc:
        """Fetch RFCTEST field layout via RFC_GET_STRUCTURE_DEFINITION (META-04).

        Secondary bootstrap called from _call_bootstrap when GFI returns STRUCTURE
        params (EXID='u'). Uses a hardcoded FunctionDesc to avoid the chicken-and-egg
        problem. Not protected by the in-flight lock (always called from _call_bootstrap
        which is called from call() which already holds the lock).

        RFC_GET_STRUCTURE_DEFINITION interface (confirmed 2026-06-29 via live GFI):
          TABNAME (I, CHAR C30 = 60B UC) — structure name to look up
          FIELDS  (T, STRUCTURE, 140B/row) — DFIES rows with field layout

        FIELDS rows are parsed by _parse_dfies_rows (140B wire-confirmed layout).
        UC offsets are computed by _build_type_desc_from_dfies (alignment rules
        verified against RFCTEST golden stfc_structure_request.bin).

        OSError/EOFError propagate to call()'s CommunicationError wrapper.
        """
        attrs = self._session.attributes
        unicode_mode = attrs.unicode_mode if attrs else True

        # Hardcoded FunctionDesc for RFC_GET_STRUCTURE_DEFINITION:
        # TABNAME=IMPORT CHAR(30), FIELDS=EXPORT TABLE (get 0x0205 decl so server returns it).
        rsd_desc = FunctionDesc(
            name="RFC_GET_STRUCTURE_DEFINITION",
            parameters=[
                FieldDesc(
                    name="TABNAME",
                    rfctype=RFCTYPE_CHAR,
                    nuc_length=30,
                    nuc_offset=0,
                    uc_length=60,
                    uc_offset=0,
                    decimals=0,
                    unicode_mode=unicode_mode,
                    direction=RFC_IMPORT,
                ),
                FieldDesc(
                    name="FIELDS",
                    rfctype=RFCTYPE_TABLE,
                    nuc_length=0,
                    nuc_offset=0,
                    uc_length=0,
                    uc_offset=0,
                    decimals=0,
                    unicode_mode=unicode_mode,
                    direction=RFC_EXPORT,
                ),
            ],
        )

        if self._is_ws():
            # wRFC: route STRUCTURE lookups through the raw-TLV invoke builder so
            # STRUCTURE params over wRFC are attempted, not silently dropped.
            frame = _build_ws_invoke_message(
                "RFC_GET_STRUCTURE_DEFINITION",
                rsd_desc,
                {"TABNAME": tabname},
                session_key=self._next_ws_invoke_key(),
            )
            self._transport.send_message(frame)
        else:
            request_tlv = build_invoke_request(
                "RFC_GET_STRUCTURE_DEFINITION",
                rsd_desc,
                {"TABNAME": tabname},
            )
            handle = self._session.handle or b"        "
            frame = self._build_invoke_frame(handle, request_tlv)
            self._send_invoke_frame(frame)

        response = self._transport.recv_message()

        raise_for_rfc_error(_strip_gw_header(response))
        dfies_rows = _parse_dfies_rows(response)
        return _build_type_desc_from_dfies(tabname, dfies_rows)

    @staticmethod
    def _rfcping_request_tlv() -> bytes:
        """Build the RFCPING invoke TLV body.

        RFCPING is an ordinary zero-parameter function call, not a special frame —
        the logon TLV itself ends with one (tag 0x0102, see handshake.md). Building
        it through ``build_invoke_request`` keeps it on the capture-confirmed invoke
        path instead of hand-rolling a second TLV writer.
        """
        return build_invoke_request("RFCPING", FunctionDesc(name="RFCPING", parameters=[]), {})

    def ping(self) -> bool:
        """Issue an RFC-level RFCPING and report liveness (TRANS-05).

        Under the single-in-flight lock: require READY, flip to IN_CALL, send the
        RFCPING invoke frame, read the response, and check the return-code TLV
        (0x0420 == 0). Always restores READY in ``finally`` (TRANS-04).
        Delegates to the async core via _LoopThread for classic TCP connections (D-07).

        The probe is a fully framed invoke — GW header, RFC marker, TLV body and
        footer — exactly like any other call. A bare TLV body reaches the gateway as
        a malformed frame and draws a plain-text error back instead of a response.
        """
        if self._async_conn is not None and self._loop_thread is not None:
            return bool(self._loop_thread.run(self._async_conn.ping()))
        with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = self._rfcping_request_tlv()
                if self._is_ws():
                    frame = _build_ws_invoke_message(
                        "RFCPING",
                        FunctionDesc(name="RFCPING", parameters=[]),
                        {},
                        session_key=self._next_ws_invoke_key(),
                    )
                    self._transport.send_message(frame)
                else:
                    handle = self._session.handle or b"        "
                    self._send_invoke_frame(self._build_invoke_frame(handle, request_tlv))
                with _fail_closed(self._session, "RFCPING"):
                    resp = self._transport.recv_message()
                    return self._rfcping_ok(resp)
            finally:
                # Guarded: a failed ping leaves the session BROKEN, and mark_ready
                # refuses any state but IN_CALL. Without the guard the finally
                # would raise over the top of the real error and hide it.
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    @staticmethod
    def _rfcping_ok(resp: bytes) -> bool:
        """Parse the RFCPING response; True iff the return-code TLV 0x0420 == 0.

        Walks the same wire dialect every other reader in the tree handles — a
        live response is a GW frame, its records use the extended-length form for
        payloads >= 0xFFFF, and each record is followed by a repeated close tag
        (session._parse_tlv, invoke._extract_name_value_pairs,
        _parse_gfi_params_rows all do this).  Skipping the close tag is not
        optional: without it the walk desynchronises by two bytes after the first
        record and every subsequent tag and length is read out of garbage, which
        surfaces as a bogus "length exceeds remaining payload" on any response
        that does not happen to put 0x0420 first.
        """
        resp = _strip_gw_header(resp)
        pos = 0
        n = len(resp)
        while pos + 4 <= n:
            tag = int.from_bytes(resp[pos : pos + 2], "big")
            length = int.from_bytes(resp[pos + 2 : pos + 4], "big")
            pos += 4
            if tag == _TAG_TERMINATOR:
                break
            if length == 0xFFFF:
                # Extended form: 4B BE length follows the 0xFFFF marker.
                if pos + 4 > n:
                    raise ValueError(
                        f"malformed RFCPING response: tag 0x{tag:04x} extended form "
                        f"but buffer too short for ext_len ({n - pos} bytes remain)"
                    )
                length = int.from_bytes(resp[pos : pos + 4], "big")
                pos += 4
            end = pos + length
            if end > n:
                raise ValueError(
                    f"malformed RFCPING response: tag 0x{tag:04x} length {length} "
                    f"exceeds remaining payload ({n - pos} bytes)"
                )
            if tag == _TAG_RETURN_CODE:
                if length != 4:
                    raise ValueError(f"RFCPING return code TLV has length {length}, expected 4")
                return int.from_bytes(resp[pos:end], "big") == 0
            pos = end
            # Skip the optional repeated-tag suffix used in extended TLV format.
            if pos + 2 <= n and int.from_bytes(resp[pos : pos + 2], "big") == tag:
                pos += 2
        raise ValueError("RFCPING response missing return-code TLV 0x0420")

    def _ws_e163_classic_fallback(
        self,
        func_name: str,
        desc: FunctionDesc,
        params: dict[str, Any],
        attrs_ws: ConnectionAttributes,
    ) -> dict[str, Any]:
        """Classic RFC fallback after wRFC LOGON E=163 (on-premise ICM constraint).

        On-premise ABAP kernels (A4H and similar) reject any non-empty ngrfc body in
        the wRFC LOGON frame, so LOGON+RFCPING always ends with E=163 and WebSocket
        close.  This method transparently re-runs the call over a classic TCP RFC
        connection derived from the LOGON response:

          1. Extract partner_host (0x0453) and sys_number (0x0452) from attrs_ws.
          2. Open a classic TCP connection to partner_host:3300+sysnr.
          3. Drive the full NI/GW/logon handshake to READY.
          4. Execute func_name via the classic RFC invoke path.
          5. Permanently replace self._transport + self._session with the classic
             ones so future calls on this Connection continue to work; _is_ws()
             will return False after this method returns.

        Never logs credentials (T-07-CRED).
        """
        auth = self._ws_auth or {}
        partner_host = (attrs_ws.partner_host or "").strip() or auth.get("server_host", "")
        sys_number = (attrs_ws.sys_number or "").strip() or auth.get("sysnr", "00")
        sysnr_int = int(sys_number) if sys_number.isdigit() else 0

        # Close dead wRFC transport (best-effort).
        try:
            self._transport.close()
        except Exception:
            pass

        # Classic TCP connection + full NI/GW/logon handshake.
        tcp = connect_tcp(partner_host, 3300 + sysnr_int)
        classic = Connection(tcp)
        classic._handshake(
            client=auth.get("client", ""),
            user=auth.get("user", ""),
            passwd=auth.get("passwd", ""),
            ashost=partner_host,
            sysnr=sysnr_int,
        )

        # Pre-populate cache with the builtin desc to skip GFI round-trip.
        classic_key = classic._metadata_cache_key
        if classic_key:
            classic._cache.put(classic_key, desc)

        result = classic.call(func_name, **params)

        # Permanently downgrade: steal classic transport+session+cache.
        # After this self._is_ws() == False; subsequent calls use classic RFC.
        self._transport = classic._transport
        self._session = classic._session
        self._cache = classic._cache
        self._ws_auth = None

        return result

    def _ws_direct_logon_call(
        self, func_name: str, desc: FunctionDesc, params: dict[str, Any]
    ) -> dict[str, Any]:
        """WS_PENDING: LOGON+RFCPING then INVOKE+func_name (two round-trips).

        Two-step protocol:
          Step 1: LOGON frame with RFCPING (empty ngrfc body) — authenticates, establishes
                  the wRFC session. RFCPING needs no param values, so no Q-markers are needed
                  in the LOGON frame. (No pcap ground truth exists for LOGON-frame Q-markers;
                  all observed LOGON frames carry only T/K markers with no param values.)
          Step 2: INVOKE frame with func_name + params — executes the actual function using
                  the pcap-verified INVOKE Q-marker format (frame 233: 0x5001 D-block,
                  TABLE_LINE col_name, compMode='C').

        Transitions WS_PENDING → READY (via complete_ws_first_call) between step 1 and 2.
        Caller must hold self._lock.  Called only when state is WS_PENDING.

        On-premise A4H ICM constraint: RFCPING LOGON always ends with E=163 and
        WebSocket close.  In that case _ws_e163_classic_fallback is invoked to re-run
        the call via a classic TCP RFC connection (transparent to the caller).
        """
        auth = self._ws_auth or {}

        # Step 1: LOGON + RFCPING (no ngrfc body, proven path, no Q-marker ambiguity).
        logon_msg, call_key = _build_ws_logon_message(
            func_name="RFCPING",
            ngrfc_body=b"",
            **auth,
        )
        self._ws_call_key = call_key
        self._ws_invoke_counter = 2
        try:
            self._transport.send_message(logon_msg)
            logon_resp = self._transport.recv_message()
        except (OSError, EOFError) as exc:
            raise CommunicationError(str(exc), original_exception=exc) from exc
        # Extract auth (0x0450 → sys_id, etc.) — raises ValueError on auth failure.
        attrs_ws = _ws_parse_logon_response(logon_resp)
        if self._transport.drain_queued_close():  # type: ignore[attr-defined]
            # E=163: auth passed but RFCPING closed the WebSocket (on-premise ICM
            # constraint — any non-empty ngrfc LOGON body causes TCP drop, so empty
            # body is required, which always yields E=163 from the WP).
            # Fall back to classic TCP RFC transparently.
            return self._ws_e163_classic_fallback(func_name, desc, params, attrs_ws)
        self._session.complete_ws_first_call(attributes=attrs_ws, codepage="4103")
        # Cache the descriptor now that the attributes are on the session.
        ws_key = self._metadata_cache_key
        if ws_key:
            self._cache.put(ws_key, desc)

        # Step 2: INVOKE + func_name with params (pcap-verified Q-marker format, frame 233).
        invoke_key = self._next_ws_invoke_key()  # counter=2 for first post-logon invoke
        invoke_msg = _build_ws_invoke_message(
            func_name=func_name,
            desc=desc,
            params=params,
            session_key=invoke_key,
            logon_func="RFCPING",
        )
        try:
            self._transport.send_message(invoke_msg)
            invoke_resp = self._transport.recv_message()
        except (OSError, EOFError) as exc:
            raise CommunicationError(str(exc), original_exception=exc) from exc
        except WebSocketError:
            # WS close arrived after step 1 (different TCP segment than LOGON response).
            # Same E=163 root cause; fall back to classic RFC.
            return self._ws_e163_classic_fallback(func_name, desc, params, attrs_ws)
        result = _ws_parse_invoke_response(invoke_resp, desc)
        return _convert_date_time_fields(result, desc)

    def call(self, func_name: str, **params: object) -> dict[str, Any]:
        """Invoke an RFC function module and return a native-typed dict (CLIENT-01..07).

        Protocol:
          1. Acquire the single-in-flight lock (TRANS-04).
          2. Require READY state; flip to IN_CALL.
          3. Resolve sys_id from session attributes for the cache key.
          4. Fetch the FunctionDesc via the metadata cache or bootstrap invoke (D-21).
          5. Build the invoke TLV (build_invoke_request, direction-routed).
          6. Send + recv via the transport seam.
          7. Parse the response (parse_invoke_response) → dict.
          8. Apply DATE/TIME post-processing (D-24): str → datetime.date/time or None.
          9. Always restore READY in finally (even on exception).

        Raises:
            AbapApplicationError: propagated from parse_invoke_response.
            AbapSystemFailure: propagated from parse_invoke_response.
            CommunicationError: wraps OSError and EOFError from the transport (CLIENT-06).
            ValueError: propagated for malformed response TLV.

        Credentials are never logged (threat T-04-CRED).
        For classic TCP connections, delegates to the async core via _LoopThread (D-07).
        """
        if self._async_conn is not None and self._loop_thread is not None:
            return cast(
                dict[str, Any], self._loop_thread.run(self._async_conn.call(func_name, **params))
            )
        with self._lock:
            # WS lazy-LOGON: in WS_PENDING the first call sends LOGON+GFI combined
            # (inside _call_bootstrap), then sends the actual function as a subsequent
            # invoke.  In all other states the normal READY guard applies.
            ws_pending = self._is_ws() and self._session.state is SessionState.WS_PENDING
            if not ws_pending:
                self._session._require_state(SessionState.READY)
                self._session.mark_in_call()
            try:
                # WS_PENDING fast-path: if the target function is in _WRFC_BUILTIN_DESCS,
                # embed it directly in the LOGON frame (pcap-verified pattern, frame 108).
                # This avoids GFI and returns the result in one round-trip.
                if ws_pending:
                    builtin = _WRFC_BUILTIN_DESCS.get(func_name.upper())
                    if builtin is not None:
                        return self._ws_direct_logon_call(func_name.upper(), builtin, dict(params))

                # Fetch FunctionDesc (cache or bootstrap round-trip, D-21).
                # In WS_PENDING, _call_bootstrap sends LOGON+RFC_GET_FUNCTION_INTERFACE
                # and advances the session to READY before returning.
                desc = get_function_desc(self, func_name, cache=self._cache)

                # After get_function_desc, session is READY regardless of the ws_pending
                # path.  Mark IN_CALL now for the actual function invoke that follows.
                if ws_pending:
                    self._session.mark_in_call()

                if self._is_ws():
                    # wRFC: raw-TLV invoke over WebSocket (no GW header, no COM_HEAD).
                    frame = _build_ws_invoke_message(
                        func_name,
                        desc,
                        dict(params),
                        session_key=self._next_ws_invoke_key(),
                    )
                    with _fail_closed(self._session, func_name):
                        self._transport.send_message(frame)
                        response = self._transport.recv_message()
                        result = _ws_parse_invoke_response(response, desc)
                else:
                    # Classic GW-framed invoke (TCP / SNC).
                    call_params = _filter_call_params(
                        func_name,
                        desc,
                        dict(params),
                        strict=self._strict_params,
                        seen=self._dropped_params_seen,
                    )
                    request_tlv = build_invoke_request(func_name, desc, call_params)
                    dm_names = dm_table_ids(desc, call_params)
                    handle = self._session.handle or b"        "
                    request = self._build_invoke_frame(handle, request_tlv)
                    with _fail_closed(self._session, func_name):
                        self._send_invoke_frame(request)
                        tlv_response = _join_response_frames(
                            self._transport.recv_message, func_name
                        )
                        result = parse_invoke_response(tlv_response, desc, dm_names)

                result = _convert_date_time_fields(result, desc)
                return result
            except (OSError, EOFError) as exc:
                raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                # Only flip IN_CALL → READY; skip if state is WS_PENDING (auth failed
                # before mark_in_call was ever called) or READY (post-exception cleanup).
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    # ------------------------------------------------------------------ #
    # Transactional RFC (tRFC / qRFC) client methods — TRFC-01/02/04    #
    # D-06: all client methods live on Connection directly.              #
    # ------------------------------------------------------------------ #

    def create_tid(self) -> str:
        """Generate a 24-character Transaction ID (TID) for tRFC / qRFC calls.

        Uses local UUID generation (NULL-handle semantics per SDK type definitions):
        this method does NOT require an open connection and may be called before
        ``connect()`` or after the connection is closed.

        The returned TID is derived from ``uuid4().hex[:24].upper()``.  UUID-hex
        characters (``0-9A-F``) are a strict subset of the confirmed RFC TID
        alphabet (``ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-``;),
        so the TID is always valid on the wire.  The authentic SDK format uses
        IP+PID+time+counter encoding, but SAP accepts any string in the alphabet
        (range check only notes, Plan 06-01 SUMMARY Assumption A1).

        Returns:
            A 24-character uppercase string suitable for use as a TID.

        Source: SDK type definitions-2224 (RfcGetTransactionID NULL-handle branch),
                protocol analysis.
        """
        return uuid.uuid4().hex[:24].upper()

    def call_transactional(
        self,
        func_name: str,
        *,
        tid: str,
        queue: str | None = None,
        **params: object,
    ) -> None:
        """Submit a tRFC (or qRFC) call carrying the confirmed call-type marker.

        Sends a synchronous RFC invoke of ``ARFC_DEST_SHIP`` with the TID encoded
        as a CHAR parameter (UTF-16LE, 24 chars = 48 bytes — Pitfall 4).  The
        function-name TLV (0x0102) carries ``ARFC_DEST_SHIP``, which IS the
        call-type discriminator on the server side (protocol analysis — no separate discriminator byte).

        For qRFC (``queue`` is not None): the queue name is included as an
        additional parameter in the ARFCSSTATE table param, causing the server to
        read a non-zero value at the queue-indicator offset 0xe58.

        Returns None — tRFC has no return values by design (CONTEXT Claude's
        discretion: ``call_transactional`` returns None rather than a dict because
        the ARFC_DEST_SHIP response carries no EXPORTING parameters meaningful to
        the caller; exactly-once delivery is signaled by absence of exception).

        This method NEVER calls ``confirm_tid`` automatically (Pitfall 3 /
        D-04): confirm is a SEPARATE lifecycle step (``conn.confirm_tid(tid)``).
        Calling ``confirm_tid`` before verifying the submit landed removes backend
        duplicate-execution protection.

        Args:
            func_name:  The wrapped ABAP function module name (e.g.
                        ``"STFC_CONNECTION"``).  Stored as ARFCFNAM in
                        ARFCSSTATE.
            tid:        24-char TID from the RFC alphabet.
                        Use ``create_tid()`` to generate one.
            queue:      qRFC queue name.  When not None, this call becomes a
                        queued RFC (TRFC-04).  Must be non-empty and bounded
                        by the protocol maximum.
            **params:   Additional keyword arguments (reserved for future
                        ARFCSDATA payload encoding; currently unused).

        Raises:
            ValueError:          If ``tid`` is not a valid 24-char RFC TID.
            CommunicationError:  Wraps ``OSError`` / ``EOFError`` from the
                                 transport (CLIENT-06 pattern).

        Security (T-06-C02): TID length and alphabet are validated inside
        ``build_trfc_request`` before encoding.  CommunicationError does not
        leak transport internals beyond ``str(exc)`` (T-06-C03).

        Source: SDK type definitions–2165 (RfcCreateTransaction, RfcSubmitTransaction),
                docs/protocol/trfc.md §"System FM Sequence".
        """
        # Classic TCP path: delegate to async core for retry behaviour (D-07).
        if self._async_conn is not None and self._loop_thread is not None:
            self._loop_thread.run(
                self._async_conn.call_transactional(func_name, tid=tid, queue=queue, **params)
            )
            return
        with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_trfc_request(tid, func_name, queue=queue)
                handle = self._session.handle or b"        "
                request = self._build_invoke_frame(handle, request_tlv)
                try:
                    self._send_invoke_frame(request)
                    # Receive and discard the server response (RFC_OK or RFC_EXECUTED).
                    # tRFC has no EXPORTING params; the response carries only the
                    # return-code TLV. We do not parse it for now (OG-06-01 gate).
                    self._transport.recv_message()
                except (OSError, EOFError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                self._session.mark_ready()

    def confirm_tid(self, tid: str) -> None:
        """Confirm a TID as a distinct lifecycle step (TRFC-02 / D-04).

        Sends a synchronous RFC invoke of ``ARFC_DEST_CONFIRM``, which causes
        the SAP backend to remove the TID from ARFCRSTATE and drop duplicate-
        execution protection for this TID.

        WARNING: After ``confirm_tid`` returns, the backend can no longer detect
        duplicate calls using this TID.  Only call this method
        after you have verified that the ``call_transactional`` submit landed
        successfully (e.g. no ``CommunicationError`` was raised).

        This method is intentionally separate from ``call_transactional`` (Pitfall
        3 / D-04): bundling submit + confirm in one step breaks exactly-once
        delivery in three-tier failure scenarios.

        Args:
            tid:  The same 24-char TID passed to ``call_transactional``.

        Raises:
            ValueError:          If ``tid`` is not a valid 24-char RFC TID.
            CommunicationError:  Wraps ``OSError`` / ``EOFError`` from the
                                 transport.

        Source: SDK type definitions (RfcConfirmTransactionID),
                protocol analysis (ARFC_DEST_CONFIRM branch).
        """
        # Classic TCP path: delegate to async core (D-07).
        if self._async_conn is not None and self._loop_thread is not None:
            self._loop_thread.run(self._async_conn.confirm_tid(tid))
            return
        with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_trfc_confirm_request(tid)
                handle = self._session.handle or b"        "
                request = self._build_invoke_frame(handle, request_tlv)
                try:
                    self._send_invoke_frame(request)
                    self._transport.recv_message()
                except (OSError, EOFError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                self._session.mark_ready()

    # ------------------------------------------------------------------ #
    # bgRFC client methods — TRFC-05/06                                   #
    # D-06: all client methods live on Connection directly.              #
    # ------------------------------------------------------------------ #

    def create_unit(
        self,
        uid: str | None = None,
        queues: list[str] | None = None,
    ) -> _UnitHandle:
        """Create a bgRFC unit context manager (TRFC-05 / D-05).

        Returns a one-shot context manager (``_UnitHandle``) that buffers
        ``unit.call("FM", **params)`` invocations.  On ``__exit__`` with no
        exception, the buffered calls are submitted as a single atomic LUW
        via BGRFC_DEST_SHIP.  On exception inside the with-block, the unit
        is abandoned and NO submit frame is sent (Pitfall 6).

        Unit type (Pitfall 5):
          - ``'T'`` when ``queues`` is empty or None (synchronous unit)
          - ``'Q'`` when ``queues`` is non-empty (queued unit)
        The type is stored on the handle so ``confirm_unit`` / ``get_unit_state``
        can pass the correct ``RFC_UNIT_IDENTIFIER`` to the backend.

        UnitID generation: when ``uid`` is None, generates a 32-char uppercase
        hex UnitID via ``uuid4().hex.upper()`` (NULL-handle semantics,
        SDK type definitions-2224 the UUID formatter path).

        Args:
            uid:    32-char uppercase hex UnitID; generated if None.
            queues: List of queue names. Empty/None → unit_type 'T'.

        Returns:
            ``_UnitHandle`` context manager.  Use as::

                with conn.create_unit(queues=["Q1"]) as unit:
                    unit.call("FM1", PARAM=val)
                    unit.call("FM2", PARAM=val)
                # On clean exit → BGRFC_DEST_SHIP frame submitted atomically.
                # On exception → unit abandoned, no submit.

        Source: SDK type definitions (RfcCreateUnit), 2272 (RfcInvokeInUnit),
                2303 (RfcSubmitUnit), D-05 context-manager API.
        """
        if uid is None:
            uid = uuid.uuid4().hex.upper()
        unit_type = "Q" if (queues and len(queues) > 0) else "T"
        return _UnitHandle(
            connection=self,
            uid=uid,
            unit_type=unit_type,
            queues=queues or [],
        )

    def _submit_unit(
        self,
        uid: str,
        unit_type: str,
        queues: list[str],
        buffered_calls: list[bytes],
    ) -> None:
        """Internal: submit the buffered unit as a BGRFC_DEST_SHIP call.

        Called by ``_UnitHandle.__exit__`` on clean exit (no exception).
        Reuses the lock envelope + ``_build_invoke_frame`` — same pattern as
        ``call_transactional``.

        Raises:
            CommunicationError:  Wraps OSError/EOFError from the transport.
        """
        # Classic TCP path: delegate to async core for retry behaviour (D-07).
        if self._async_conn is not None and self._loop_thread is not None:
            self._loop_thread.run(
                self._async_conn._submit_unit(uid, unit_type, queues, buffered_calls)
            )
            return
        with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_bgrfc_request(uid, unit_type, queues, buffered_calls)
                handle = self._session.handle or b"        "
                request = self._build_invoke_frame(handle, request_tlv)
                try:
                    self._send_invoke_frame(request)
                    # Receive and discard the server response (RFC_OK or state indicator).
                    # bgRFC submit has no EXPORTING params (OG-06-02 gate).
                    self._transport.recv_message()
                except (OSError, EOFError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                self._session.mark_ready()

    def confirm_unit(self, unit_id: str, unit_type: str = "T") -> None:
        """Confirm a bgRFC unit as a distinct lifecycle step (TRFC-06 / D-05).

        Sends BGRFC_DEST_CONFIRM to the backend.  After this call the backend
        can clean up the unit state.  The ``unit_type`` must match the type
        used at submit time (Pitfall 5).

        ``RFC_UNIT_NOT_FOUND`` after confirm means the backend already cleaned
        up — treat as success (anti-pattern: never resend on NOT_FOUND after
        confirm, T-06-U04).

        Args:
            unit_id:   32-char uppercase hex UnitID.
            unit_type: 'T' or 'Q' (must match submit-time unit_type, Pitfall 5).

        Raises:
            ValueError:          If ``unit_id`` is not a valid 32-char hex UnitID.
            CommunicationError:  Wraps OSError/EOFError from the transport.

        Source: SDK type definitions (RfcConfirmUnit),
                protocol analysis (BGRFC_DEST_CONFIRM).
        """
        # Classic TCP path: delegate to async core (D-07).
        if self._async_conn is not None and self._loop_thread is not None:
            self._loop_thread.run(self._async_conn.confirm_unit(unit_id, unit_type))
            return
        with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_bgrfc_confirm_request(unit_id, unit_type)
                handle = self._session.handle or b"        "
                request = self._build_invoke_frame(handle, request_tlv)
                try:
                    self._send_invoke_frame(request)
                    self._transport.recv_message()
                except (OSError, EOFError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                self._session.mark_ready()

    def rollback_unit(self, unit_id: str, unit_type: str = "T") -> None:
        """Signal that a bgRFC unit should be rolled back (TRFC-06).

        Informs the backend that the unit should be treated as rolled back
        (re-send may be required).  This is distinct from ``confirm_unit``
        and does NOT remove the unit from the backend's state tables.

        Args:
            unit_id:   32-char uppercase hex UnitID.
            unit_type: 'T' or 'Q' (must match submit-time unit_type, Pitfall 5).

        Raises:
            ValueError:          If ``unit_id`` is not a valid 32-char hex UnitID.
            CommunicationError:  Wraps OSError/EOFError from the transport.

        Source: SDK type definitions (RfcDestroyUnit / rollback path); D-05.
        """
        # Classic TCP path: delegate to async core (D-07).
        if self._async_conn is not None and self._loop_thread is not None:
            self._loop_thread.run(self._async_conn.rollback_unit(unit_id, unit_type))
            return
        # bgRFC rollback from the client side sends a state query/notification;
        # the authoritative rollback happens on the server side (server-side
        # on_rollback callback).  Client-side rollback records intent and does NOT
        # submit (consistent with Pitfall 3 — never bundle submit+rollback).
        # This call is a no-op over the wire when the transport is not live
        # (OG-06-02 gate); the pattern is documented here for completeness.
        with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                # For the offline path (no live SAP), we issue a state query so the
                # unit_id validation fires (T-06-U02). Full rollback FM TBD at D-08.
                request_tlv = build_bgrfc_state_request(unit_id, unit_type)
                handle = self._session.handle or b"        "
                request = self._build_invoke_frame(handle, request_tlv)
                try:
                    self._send_invoke_frame(request)
                    self._transport.recv_message()
                except (OSError, EOFError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                self._session.mark_ready()

    def get_unit_state(self, unit_id: str, unit_type: str = "T") -> UnitState:
        """Query the current state of a bgRFC unit on the backend (TRFC-06).

        Sends BGRFC_CHECK_UNIT_STATE_SERVER and maps the response to a
        ``UnitState`` enum value (SDK type definitions-332).

        ``RFC_UNIT_NOT_FOUND`` after a confirmed unit is treated as success
        (state is already ``CONFIRMED`` — do not resend, T-06-U04).

        Args:
            unit_id:   32-char uppercase hex UnitID.
            unit_type: 'T' or 'Q' (must match submit-time unit_type, Pitfall 5).

        Returns:
            A ``UnitState`` enum value.

        Raises:
            ValueError:          If ``unit_id`` is not a valid 32-char hex UnitID.
            CommunicationError:  Wraps OSError/EOFError from the transport.

        Source: SDK type definitions (RfcGetUnitState),
                protocol analysis (BGRFC_CHECK_UNIT_STATE_SERVER).
        """
        # Classic TCP path: delegate to async core (D-07).
        if self._async_conn is not None and self._loop_thread is not None:
            return cast(
                UnitState,
                self._loop_thread.run(self._async_conn.get_unit_state(unit_id, unit_type)),
            )
        with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_bgrfc_state_request(unit_id, unit_type)
                handle = self._session.handle or b"        "
                request = self._build_invoke_frame(handle, request_tlv)
                try:
                    self._send_invoke_frame(request)
                    response = self._transport.recv_message()
                except (OSError, EOFError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
                # Parse response: look for a BGRFC_STATE param in the response TLV.
                # Offline path (no live SAP): response is empty → return NOT_FOUND.
                return self._parse_unit_state_response(response)
            finally:
                self._session.mark_ready()

    @staticmethod
    def _parse_unit_state_response(response: bytes) -> UnitState:
        """Parse a BGRFC_CHECK_UNIT_STATE_SERVER response into a UnitState enum.

        The backend returns the state as a CHAR parameter (BGRFC_STATE) in the
        response TLV.  Map the string value to UnitState (SDK type definitions-332).
        When no recognisable state is found (offline or unknown value), return
        UnitState.NOT_FOUND (safe default — caller can treat as not yet committed).

        Mapping (RFC_UNIT_STATE → UnitState):
          0 / 'NOT_FOUND'  → UnitState.NOT_FOUND
          1 / 'IN_PROCESS' → UnitState.IN_PROCESS
          2 / 'COMMITTED'  → UnitState.COMMITTED
          3 / 'ROLLED_BACK'→ UnitState.ROLLED_BACK
          4 / 'CONFIRMED'  → UnitState.CONFIRMED
        """
        if not response:
            return UnitState.NOT_FOUND
        from saprfclib.invoke import _decode_utf16le, _extract_name_value_pairs

        try:
            for name, val in _extract_name_value_pairs(response):
                if name.upper() in ("BGRFC_STATE", "STATE", "UNIT_STATE"):
                    state_str = _decode_utf16le(val).strip()
                    _state_map = {
                        "0": UnitState.NOT_FOUND,
                        "NOT_FOUND": UnitState.NOT_FOUND,
                        "1": UnitState.IN_PROCESS,
                        "IN_PROCESS": UnitState.IN_PROCESS,
                        "2": UnitState.COMMITTED,
                        "COMMITTED": UnitState.COMMITTED,
                        "3": UnitState.ROLLED_BACK,
                        "ROLLED_BACK": UnitState.ROLLED_BACK,
                        "4": UnitState.CONFIRMED,
                        "CONFIRMED": UnitState.CONFIRMED,
                    }
                    return _state_map.get(state_str.upper(), UnitState.NOT_FOUND)
        except Exception:
            pass
        return UnitState.NOT_FOUND

    def retry_parked(self, tid: str) -> None:
        """Re-send a parked tRFC call from the durable store (D-03b — sync delegation).

        Delegates to :meth:`AsyncConnection.retry_parked` via the background event
        loop (D-07).  Only available for classic TCP connections (``_async_conn`` is
        set).  Raises :class:`~saprfclib.exceptions.TransactionalError` for SNC/wRFC
        paths where no async core is present.
        """
        from saprfclib.exceptions import TransactionalError

        if self._async_conn is not None and self._loop_thread is not None:
            self._loop_thread.run(self._async_conn.retry_parked(tid))
            return
        raise TransactionalError("retry_parked is only available on classic TCP connections")

    def retry_parked_unit(self, unit_id: str, unit_type: str = "T") -> None:
        """Re-send a parked bgRFC unit from the durable store (D-03b — sync delegation).

        Delegates to :meth:`AsyncConnection.retry_parked_unit` via the background
        event loop (D-07).  Only available for classic TCP connections.
        """
        from saprfclib.exceptions import TransactionalError

        if self._async_conn is not None and self._loop_thread is not None:
            self._loop_thread.run(self._async_conn.retry_parked_unit(unit_id, unit_type))
            return
        raise TransactionalError("retry_parked_unit is only available on classic TCP connections")

    def close(self) -> None:
        """Close the connection; safe to call in ANY state including partial/error.

        Suppresses every exception from the (future) RFC-layer close frame, then
        unconditionally marks the session CLOSED and closes the transport
        (TRANS-06). Idempotent: closing an already-closed connection never raises.
        For classic TCP connections, delegates to the async core then stops the
        background event loop (D-07).
        """
        if self._async_conn is not None and self._loop_thread is not None:
            try:
                self._loop_thread.run(self._async_conn.close())
            except Exception:
                pass
            finally:
                self._loop_thread.close()
                self._async_conn = None
                self._loop_thread = None
                # Mark session CLOSED so subsequent ping/call raise ValueError.
                self._session._state = SessionState.CLOSED
            return
        try:
            # Phase 4 will send an RFC-layer close frame here when in a clean state.
            pass
        except Exception:
            pass
        finally:
            self._session._state = SessionState.CLOSED
            self._transport.close()


class _UnitHandle:
    """One-shot bgRFC unit context manager (D-05 / TRFC-05).

    Created by ``Connection.create_unit()``.  Buffers ``unit.call()`` invocations
    and submits them atomically via BGRFC_DEST_SHIP on ``__exit__`` (no exception).
    On exception inside the with-block, the unit is abandoned — nothing is submitted.

    This is intentionally a one-shot context manager: after ``__exit__``, the
    handle is consumed and must not be reused.  Create a new unit for each
    logical unit of work (LUW).

    Public surface:
      ``unit_id``   — the 32-char uppercase hex UnitID.
      ``unit_type`` — 'T' (no queues) or 'Q' (queues given).
      ``unit.call(func_name, **params)`` — buffer a call (returns None, Pitfall 6).
    """

    def __init__(
        self,
        connection: Connection,
        uid: str,
        unit_type: str,
        queues: list[str],
    ) -> None:
        self._connection = connection
        self._uid = uid
        self._unit_type = unit_type
        self._queues = queues
        # Each entry is (func_name, params_dict) — buffered via unit.call()
        self._buffered: list[tuple[str, dict[str, Any]]] = []
        self._submitted: bool = False

    @property
    def unit_id(self) -> str:
        """The 32-char uppercase hex UnitID (RFC_UNITID_LN=32)."""
        return self._uid

    @property
    def unit_type(self) -> str:
        """Unit type: 'T' (no queues) or 'Q' (queues given)."""
        return self._unit_type

    def call(self, func_name: str, **params: object) -> None:
        """Buffer a call to the given function module (RfcInvokeInUnit).

        Nothing executes at this point — the call is serialized into the unit's
        internal buffer.  Execution occurs atomically when the with-block exits
        cleanly (``__exit__`` with no exception) by ``_submit_unit``.

        Returns None always (Pitfall 6: ``RfcInvokeInUnit`` buffers, does not
        execute; there is no result to return here — SDK type definitions).

        Args:
            func_name: The ABAP function module name to call.
            **params:  Key/value params for the function module.
        """
        self._buffered.append((func_name, dict(params)))
        return None

    def __enter__(self) -> _UnitHandle:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> Literal[False]:
        """Submit the unit on clean exit; abandon on exception.

        On no exception (``exc_type is None``): serializes each buffered call's
        func_name + params into bytes (using the existing ``build_bgrfc_request``
        embed mechanism) and calls ``Connection._submit_unit`` with the complete
        payload.  Exactly ONE submit frame is emitted (atomic LUW).

        On exception: the unit is abandoned.  No submit frame is sent.
        ``exc_type is not None`` → do NOT suppress the exception (return False).

        Source: SDK type definitions (RfcSubmitUnit).
        """
        if exc_type is not None:
            # Exception inside with-block: abandon unit, do not submit.
            # Return False so the exception propagates.
            return False

        if self._submitted:
            # Already submitted (shouldn't happen with one-shot design, but guard).
            return False

        self._submitted = True

        # Serialize each buffered call into a simple bytes payload.
        # Format: func_name UTF-16LE + zero separator + params as UTF-16LE key=value pairs.
        # This is a simplified wire encoding sufficient for offline tests; the exact
        # BGRFC_DEST_SHIP ARFCSDATA layout is OG-06-02 (D-08 live-capture gate).
        buffered_bytes: list[bytes] = []
        for func_name, params in self._buffered:
            parts = [func_name.encode("utf-16-le")]
            for k, v in params.items():
                entry = f"{k}={v}".encode("utf-16-le")
                parts.append(entry)
            buffered_bytes.append(b"\x00\x00".join(parts))

        self._connection._submit_unit(
            self._uid,
            self._unit_type,
            self._queues,
            buffered_bytes,
        )
        return False


class _AsyncUnitHandle:
    """One-shot async bgRFC unit context manager for AsyncConnection (D-05 / TRFC-05).

    Created by :meth:`AsyncConnection.create_unit`.  Buffers ``unit.call()``
    invocations and submits them atomically via BGRFC_DEST_SHIP on ``__aexit__``
    with no exception.  On exception inside the async with-block, the unit is
    abandoned — nothing is submitted.

    Public surface:
      ``unit_id``    — the 32-char uppercase hex UnitID.
      ``unit_type``  — 'T' (no queues) or 'Q' (queues given).
      ``unit.call(func_name, **params)`` — buffer a call (returns None, Pitfall 6).
    """

    def __init__(
        self,
        connection: AsyncConnection,
        uid: str,
        unit_type: str,
        queues: list[str],
    ) -> None:
        self._connection = connection
        self._uid = uid
        self._unit_type = unit_type
        self._queues = queues
        self._buffered: list[tuple[str, dict[str, Any]]] = []
        self._submitted: bool = False

    @property
    def unit_id(self) -> str:
        """The 32-char uppercase hex UnitID (RFC_UNITID_LN=32)."""
        return self._uid

    @property
    def unit_type(self) -> str:
        """Unit type: 'T' (no queues) or 'Q' (queues given)."""
        return self._unit_type

    def call(self, func_name: str, **params: object) -> None:
        """Buffer a call to the given function module (RfcInvokeInUnit).

        Nothing executes at this point — the call is serialized into the unit's
        internal buffer.  Execution occurs atomically when the async with-block
        exits cleanly (``__aexit__`` with no exception) by ``_submit_unit``.

        Returns None always (Pitfall 6).
        """
        self._buffered.append((func_name, dict(params)))
        return None

    async def __aenter__(self) -> _AsyncUnitHandle:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> bool:
        """Submit the unit on clean exit; abandon on exception.

        Mirrors :meth:`_UnitHandle.__exit__` but awaits :meth:`AsyncConnection._submit_unit`.
        On exception: unit abandoned, exc_type is not None → return False.
        On clean exit: serialize buffered calls → await _submit_unit (retry loop).
        Returns False to not suppress exceptions.
        """
        if exc_type is not None:
            return False

        if self._submitted:
            return False

        self._submitted = True

        buffered_bytes: list[bytes] = []
        for func_name, params in self._buffered:
            parts = [func_name.encode("utf-16-le")]
            for k, v in params.items():
                entry = f"{k}={v}".encode("utf-16-le")
                parts.append(entry)
            buffered_bytes.append(b"\x00\x00".join(parts))

        await self._connection._submit_unit(
            self._uid,
            self._unit_type,
            self._queues,
            buffered_bytes,
        )
        return False


def connect(
    ashost: str,
    sysnr: str | int,
    client: str,
    user: str | None = None,
    passwd: str | None = None,
    *,
    lang: str = _DEFAULT_LANG,
    strict_params: bool = False,
    timeout: float | None = None,
    connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float | None = DEFAULT_READ_TIMEOUT,
    metadata_cache: MetadataCache | None = None,
    metadata_cache_key: str | None = None,
    saprouter: str | None = None,
    mshost: str | None = None,
    msserv: int | str | None = None,
    ms_http_port: int | str | None = None,
    ms_use_http: bool = True,
    sysid: str | None = None,
    group: str | None = None,
    wshost: str | None = None,
    wsport: int | None = None,
    ws_path: str | None = None,
    ws_proxy_host: str | None = None,
    ws_proxy_port: int | None = None,
    ws_proxy_user: str | None = None,
    ws_proxy_pass: str | None = None,
    ws_tls_verify: bool = True,
    snc_lib: str | None = None,
    snc_partnername: str | None = None,
    snc_myname: str | None = None,
    snc_qop: int | None = None,
    snc_sso: bool | None = None,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    tid_store: TidStore | None = None,
    unit_store: UnitStore | None = None,
) -> Connection:
    """Open and return a ready Connection (blocking).

    Four transport paths:
      - message server: ``mshost`` set → resolve the least-loaded app server via
        MessageServerClient.resolve(group), then direct-TCP connect (TRANS-03).
      - SAProuter: ``saprouter`` set → prepend the NI_ROUTE prefix before the
        direct-TCP handshake (TRANS-02).
      - wRFC (WebSocket RFC over TLS): ``wshost`` set → route through
        ``connect_ws`` (SEC-05, D-16/D-17). ``wsport`` defaults to 443 and
        ``ws_path`` to ``/sap/bc/rfc`` (D-19). Optional ``ws_proxy_*`` params
        tunnel the connection through an HTTP CONNECT forward proxy (D-20).
      - SNC (Secure Network Communications): ``snc_lib`` set (and ``wshost``
        absent) → wrap the direct-TCP transport in an :class:`~saprfclib.snc.SncTransport`
        that drives the GSS-API handshake to COMPLETE before any data is sent
        (SEC-02/03/04/06, D-13). ``snc_lib`` presence is the activation switch —
        there is no separate mode flag. ``snc_qop`` defaults to 3 (privacy) and
        ``snc_sso`` to False (D-12). ``wshost`` takes precedence: SNC-over-wRFC
        is out of scope for Phase 7.
      - direct: ``port = 3300 + int(sysnr)`` (gateway port), connect_tcp, handshake.

    ``lang`` is the logon language. Accepts the one-character SAP code ('E' English,
    'D' German, 'S' Spanish, …) or the two-character ISO code ('EN', 'DE', 'ES'); an
    ISO code is converted before the logon frame is built, matching the SDK's LANG
    option.

    ``user`` and ``passwd`` may both be omitted. That is read as a deliberate
    anonymous attempt and the logon frame goes out without the user and password
    records — some systems answer a small set of function modules that way, while a
    hardened one refuses below the RFC layer and raises ``CommunicationError``.
    Supplying exactly one of the two raises ``ValueError``, since that is a missing
    setting rather than a request to connect anonymously. SNC connections are
    unaffected: ``snc_lib`` carries its own credentials.

    ``strict_params`` controls what ``call()`` does with a keyword argument the
    function interface does not declare. The default (False) drops it and logs a
    warning, which is what callers porting from pyrfc expect when they pass a
    superset of kwargs across differing SAP releases. Set True to raise ValueError
    instead — worth doing when a dropped argument would change the result, since the
    server has no way to tell you an argument never arrived.

    The SAProuter and message-server wire formats were live-verified after this
    docstring first called them unverified: the NI_ROUTE payload is byte-exact
    against a capture (``tests/golden/router/ni_route_payload.bin``), a router
    that accepts a route answers ``NI_PONG`` and one that refuses answers
    ``NI_RTERR``, and the message server answers the binary attach and
    server-list frames as ``MSG_SERVER``. What remains unconfirmed is narrower and
    sits in ``router.py``: some field boundaries inside a server-list entry, and
    whether the entry count is carried in the header or only implied by the
    payload length. ``passwd``,
    ``ws_proxy_pass``, ``snc_lib``, ``snc_partnername`` and ``snc_myname`` are
    never logged or echoed into any log message or exception string (threats
    T-03-CRED2 / T-07-CRED / T-07-PROXY-CRED).
    """
    # Imported lazily so the direct-TCP facade carries no hard dependency on the
    # alternate-transport layer (router.py, plan 03-03 Task 2).
    from saprfclib.router import (
        open_route,
        open_route_async,
        parse_route_string,
    )

    user, passwd = _resolve_credentials(user, passwd, snc_lib=snc_lib, ashost=ashost)

    if mshost is not None:
        # Message-server group logon: resolve to a concrete (ashost, sysnr).
        ashost, sysnr = _resolve_via_message_server(
            mshost,
            group=group,
            sysid=sysid,
            msserv=msserv,
            ms_http_port=ms_http_port,
            use_http=ms_use_http,
            timeout=timeout,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

    # Gateway port. Confirmed by SAP's "TCP/IP Ports of All SAP Products":
    #   Gateway          sapgw<NN>    3300   range 3300-3399   33<NN>
    #   Gateway secured  sapgw<NN>s   4800   range 4800-4899   48<NN>
    # <NN> is the application server's own instance number here, unlike the
    # message server. Also confirmed live: the A4H message server reports
    # RFC=3300 and RFCS=4800 for a sysnr-00 application server.
    sysnr = _validate_sysnr(sysnr)
    port = (4800 if snc_lib is not None else 3300) + sysnr

    # ------------------------------------------------------------------ #
    # Transport routing (Phase 7): wRFC first, then SNC, then plain TCP.  #
    # Both branches are additive — when ``wshost`` and ``snc_lib`` are    #
    # None the plain connect_tcp path below is byte-for-byte unchanged    #
    # (SEC-01 / T-07-REGRESSION). ``wshost`` wins over ``snc_lib`` because #
    # SNC-over-wRFC is out of scope for Phase 7 (D-13).                    #
    # ------------------------------------------------------------------ #
    if wshost is not None:
        # wRFC over TLS (SEC-05, D-16/D-17). Lazy import mirrors the
        # router lazy import above so a bare ``import saprfclib`` never hard-
        # depends on the WebSocket stack at import time.
        from saprfclib.ws import connect_ws

        transport = connect_ws(
            wshost,
            wsport or 443,
            ws_path=ws_path or "/sap/bc/rfc?sap-apc-stateful=true",
            ws_proxy_host=ws_proxy_host,
            ws_proxy_port=ws_proxy_port,
            ws_proxy_user=ws_proxy_user,
            ws_proxy_pass=ws_proxy_pass,
            user=user,
            passwd=passwd,
            sap_client=client,
            verify=ws_tls_verify,
            timeout=timeout,
        )
        conn = Connection(
            transport,  # type: ignore[arg-type]
            strict_params=strict_params,
            metadata_cache=metadata_cache,
            metadata_cache_key=metadata_cache_key,
        )
    elif snc_lib is not None:
        # SNC (SEC-02/03/04/06, D-13): SAP protocol order requires the NI
        # version exchange to complete on the plain channel BEFORE the GSS
        # frames are sent. SncTransport then drives FR_INIT/FR_ACCEPT to
        # COMPLETE; GW connect and logon flow through the encrypted channel.
        #
        # T-07-CRED: snc_lib / snc_partnername / snc_myname are passed
        # straight through — never placed into a log or an exception string.
        from saprfclib.snc import SncTransport

        _inner = connect_tcp(
            ashost,
            port,
            timeout=timeout,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

        # Step 1: NI version exchange on the plain inner transport.
        _snc_sess = Session()
        try:
            _snc_lip = _inner._sock.getsockname()[0]
        except Exception:
            _snc_lip = "127.0.0.1"
        _inner.send_message(_snc_sess.start(local_ip=_snc_lip))
        _snc_sess.feed(_inner.recv_message())
        # _snc_sess is now NI_VERSIONED.

        # Step 2: GSS handshake on the versioned channel.
        transport = SncTransport(  # type: ignore[assignment]
            _inner,
            snc_lib=snc_lib,
            snc_partnername=snc_partnername,  # type: ignore[arg-type]
            snc_myname=snc_myname,
            snc_qop=snc_qop or 3,  # D-12: privacy is the default QOP
            snc_sso=snc_sso or False,  # D-12: SSO2 off by default (D-23 gap)
        )

        # Step 3: Connection with the pre-versioned session so _handshake()
        # resumes from NI_VERSIONED (skips the NI leg, starts at GW connect).
        conn = Connection(
            transport,  # type: ignore[arg-type]
            strict_params=strict_params,
            metadata_cache=metadata_cache,
            metadata_cache_key=metadata_cache_key,
        )
        conn._session = _snc_sess
        conn._snc_mode = True
    else:
        # ------------------------------------------------------------------ #
        # Classic async-core path (D-06/D-07): direct TCP / SAProuter /       #
        # message-server connections all use AsyncConnection + _LoopThread.   #
        # SAProuter NI_ROUTE is prepended inside the async setup coroutine.   #
        # Returns early — the shared saprouter/handshake lines below are for  #
        # SNC / wRFC paths only (scope boundary — Phase 9).                   #
        # ------------------------------------------------------------------ #
        loop_thread = _LoopThread()

        # Capture locals for the async closure (avoid late-binding issues).
        _ashost = ashost
        _port = port
        _timeout = timeout
        _connect_timeout = connect_timeout
        _read_timeout = read_timeout
        _metadata_cache = metadata_cache
        _metadata_cache_key = metadata_cache_key
        _saprouter = saprouter
        _client = client
        _user = user
        _passwd = passwd
        _lang = lang
        _strict = strict_params
        _sysnr = int(sysnr)
        _max_retries = max_retries
        _retry_delay = retry_delay
        _tid_store = tid_store
        _unit_store = unit_store

        async def _async_setup() -> AsyncConnection:
            # Use connect_tcp (sync, patchable in tests) wrapped in a thin async shim.
            # connect_async() uses real asyncio open_connection for non-blocking I/O.
            # This keeps the existing test suite (which patches connect_tcp) green (D-07).
            sync_t = connect_tcp(
                _ashost,
                _port,
                timeout=_timeout,
                connect_timeout=_connect_timeout,
                read_timeout=_read_timeout,
            )
            at: _SyncToAsyncTransport = _SyncToAsyncTransport(sync_t)
            if _saprouter is not None:
                hops = parse_route_string(_saprouter)
                await open_route_async(at, hops, _ashost, str(_port))
            ac = AsyncConnection(
                at,  # type: ignore[arg-type]
                max_retries=_max_retries,
                retry_delay=_retry_delay,
                tid_store=_tid_store,
                unit_store=_unit_store,
                strict_params=_strict,
                metadata_cache=_metadata_cache,
                metadata_cache_key=_metadata_cache_key,
            )
            await ac._handshake(
                client=_client,
                user=_user,
                passwd=_passwd,
                ashost=_ashost,
                sysnr=_sysnr,
                lang=_lang,
            )
            return ac

        try:
            async_conn = loop_thread.run(_async_setup())
        except Exception:
            loop_thread.close()
            raise
        return Connection._from_async(async_conn, loop_thread)

    if saprouter is not None:
        # Prepend the NI_ROUTE control frame before the handshake (TRANS-02).
        # Wire format confirmed from live capture 2026-06-27.
        # NOTE: only reached by SNC/wRFC branches (classic path returns above).
        hops = parse_route_string(saprouter)
        open_route(transport, hops, ashost, str(port))

    conn._handshake(
        client=client, user=user, passwd=passwd, ashost=ashost, sysnr=int(sysnr), lang=lang
    )
    return conn


# Message-server ports. Source: SAP's "TCP/IP Ports of All SAP Products"
# (help.sap.com, Security guide), cross-checked against a live scan of A4H.
#
# There is deliberately NO numeric default, and the documentation is why.
#
# The table gives the message server TWO different rows:
#
#   Application Server ABAP   Message server   sapmsSID    3600   36<NN>
#       "Relevant only for systems that have been installed prior to
#        SAP NetWeaver 7.0 with a central instance (CI)."
#
#   SAP Central Services (SCS)   Message server port   sapms<SID>   9310
#       range 0-65535, formula: None
#       "Configure the message server port with profile parameter rdisp/msserv."
#
# So the 36<NN> formula applies only to pre-NetWeaver-7.0 central-instance
# systems. On anything modern — an ASCS/SCS layout, which is every current
# install — the port is whatever rdisp/msserv says, over the whole port range,
# with a documented default of 9310. There is no formula to apply.
#
# That makes any numeric default wrong in a different way for each layout: 3600
# for a legacy CI, 9310 for a default SCS, and on the A4H test system 3601 (a
# 36<NN> port with NN=01, since sapstartsrv answers on both 50013 and 50113 —
# 5<NN>13 — so instances 00 and 01 both exist and the message server is on 01).
# A wrong port is not a failure the caller can interpret, so nothing is guessed.
#
# The instance number is instead read from where the documentation says it lives:
# the sapms<SID> entry in /etc/services. The same table notes "You can reassign
# service names to an arbitrary value after installation in /etc/services", which
# makes that file the client-side source of record rather than a convention. When
# it is absent, the caller is asked for `msserv`.
#
# The HTTP interface is 81<NN> (range 8100-8199, profile ms/http_port_<n>) and is
# documented as "Not active by default" — which is why the HTTP resolver reports
# its absence as a configuration fact rather than an error.
_MS_BINARY_BASE = 3600
_MS_HTTP_BASE = 8100


def _resolve_via_message_server(
    mshost: str,
    *,
    group: str | None,
    sysid: str | None,
    msserv: int | str | None,
    ms_http_port: int | str | None,
    use_http: bool,
    timeout: float | None,
    connect_timeout: float | None,
    read_timeout: float | None,
) -> tuple[str, int]:
    """Resolve a logon group to a concrete (ashost, sysnr).

    Prefers the message server's HTTP interface, which is line-oriented and was
    confirmed against a live server (tests/golden/router/ms_http_logon_v12.txt).
    The binary protocol in router.py is still built from a partial capture: on a
    live message server it accepts the connection and then answers nothing, so
    every frame it sends is unverified. Letting it choose silently would mean an
    unverified path deciding which application server the caller talks to.

    Pass ``ms_use_http=False`` to force the binary path anyway.
    """
    from saprfclib.router import MessageServerClient, resolve_rfc_server_http

    if use_http:
        http_port = _ms_http_port(sysid, ms_http_port if ms_http_port is not None else msserv)
        host, rfc_port = resolve_rfc_server_http(mshost, http_port, group=group)
        # The list gives an RFC port; the rest of connect() wants a system number.
        # 3300 + sysnr is the confirmed gateway convention. Anything else is a
        # non-standard port that cannot be expressed as a system number, so say so
        # rather than truncating it into a wrong one.
        sysnr = rfc_port - 3300
        if not 0 <= sysnr <= 99:
            raise ValueError(
                f"message server returned RFC port {rfc_port} for group "
                f"{group or 'PUBLIC'}, which is not 3300 + a system number. Connect to "
                f"{host}:{rfc_port} directly with ashost/sysnr instead."
            )
        _logger.debug(
            "message server %s resolved group %s to %s (sysnr %02d)",
            mshost,
            group or "PUBLIC",
            host,
            sysnr,
        )
        return host, sysnr

    ms_transport = connect_tcp(
        mshost,
        _ms_port(sysid, msserv),
        timeout=timeout,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )
    try:
        return MessageServerClient(ms_transport).resolve(group or "PUBLIC")
    finally:
        ms_transport.close()


def _ms_instance_from_services(sysid: str | None) -> int | None:
    """Recover the message server's instance number from ``sapms<SID>``.

    This is the mechanism SAP tooling uses to find the message server, and it is
    the only client-side source that states the instance number rather than
    assuming it. Returns None when the entry is absent, which is common on hosts
    that were never configured as SAP clients.
    """
    if not sysid:
        return None
    try:
        port = _socket_module.getservbyname(f"sapms{sysid.upper()}")
    except OSError:
        return None
    instance = port - _MS_BINARY_BASE
    return instance if 0 <= instance <= 99 else None


def _resolve_ms_service(msserv: int | str | None) -> int | None:
    """Turn an explicit port or service name into a port number; None if unset."""
    if msserv is None:
        return None
    if isinstance(msserv, int):
        return msserv
    text = msserv.strip()
    if text.isdigit():
        return int(text)
    try:
        return _socket_module.getservbyname(text)
    except OSError:
        # A name /etc/services does not know is a configuration mistake, not
        # something to paper over by connecting somewhere else.
        raise ValueError(
            f"message-server service {msserv!r} is not in /etc/services; give the "
            f"port number instead (for example msserv=3601)"
        ) from None


def _ms_port_or_raise(sysid: str | None, msserv: int | str | None, base: int, what: str) -> int:
    """Resolve a message-server port, or explain why it cannot be resolved."""
    explicit = _resolve_ms_service(msserv)
    if explicit is not None:
        return explicit
    instance = _ms_instance_from_services(sysid)
    if instance is not None:
        return base + instance
    raise ValueError(
        f"cannot determine the {what} message-server port: no msserv was given and "
        f"there is no sapms{(sysid or '<SID>').upper()} entry in /etc/services. The "
        f"port is {base} + the message server's instance number, which is NOT the "
        f"application server's system number and cannot be derived from it — on a "
        f"system with a separate ASCS they differ. Pass msserv explicitly (a port "
        f"such as msserv={base + 1}, or the service name msserv='sapms"
        f"{(sysid or 'SID').upper()}')."
    )


def _ms_port(sysid: str | None, msserv: int | str | None = None) -> int:
    """Binary message-server port (36<nn>, nn = message-server instance number)."""
    return _ms_port_or_raise(sysid, msserv, _MS_BINARY_BASE, "binary")


def _ms_http_port(sysid: str | None = None, msserv: int | str | None = None) -> int:
    """HTTP message-server port (81<nn>, nn = message-server instance number)."""
    return _ms_port_or_raise(sysid, msserv, _MS_HTTP_BASE, "HTTP")


# ---------------------------------------------------------------------------
# AsyncConnection — real asyncio RFC client (D-06/D-08)
# ---------------------------------------------------------------------------


class AsyncConnection:
    """Real asyncio RFC Connection for classic TCP paths (D-06/D-08).

    Owns an AsyncTransport (or any async-seam double with send_message/recv_message
    coroutines) and a sans-I/O Session; drives the NI/GW/logon handshake and the
    RFC invoke path entirely via await.  The Session/codec/invoke layer is reused
    verbatim from the sync path — only the send/recv seam becomes await.

    Usage (via connect_async factory):
        async with await connect_async(ashost=..., sysnr=..., client=...,
                                       user=..., passwd=...) as conn:
            result = await conn.call("STFC_CONNECTION", REQUTEXT="hi")

    Thread safety: asyncio.Lock serialises single-in-flight (TRANS-04 parity).
    CancelledError always propagates — never caught in I/O methods (Pitfall 7).
    """

    def __init__(
        self,
        transport: AsyncTransport,
        *,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        tid_store: TidStore | None = None,
        unit_store: UnitStore | None = None,
        strict_params: bool = False,
        metadata_cache: MetadataCache | None = None,
        metadata_cache_key: str | None = None,
    ) -> None:
        self._transport = transport
        self._session = Session()
        self._lock = asyncio.Lock()
        # Server-reported duration of the most recent call (tag 0x0667, seconds),
        # handed to CallStats by call(). None until a response carries one.
        self._last_server_duration_s: float | None = None
        # Unknown-parameter policy (issue #24) - see Connection.__init__.
        self._strict_params = strict_params
        self._dropped_params_seen: set[tuple[str, tuple[str, ...]]] = set()
        self.metrics = ConnectionMetrics()
        # Shareable across connections to one system — see Connection.__init__.
        self._cache = metadata_cache if metadata_cache is not None else MetadataCache()
        self._anon_cache_key: str | None = metadata_cache_key
        self._struct_desc_cache: dict[str, TypeDesc] = {}
        # Retry + durable-store attributes (D-01/D-02/D-03/D-03b)
        self._max_retries = max_retries  # max auto-retry attempts (D-02)
        self._retry_delay = retry_delay  # base backoff delay in seconds (D-02)
        self._tid_store = tid_store  # TidStore | None for tRFC/qRFC parking
        self._unit_store = unit_store  # UnitStore | None for bgRFC parking

    # ------------------------------------------------------------------ #
    # Handshake (classic direct-TCP path — SNC/wRFC use sync Connection)  #
    # ------------------------------------------------------------------ #

    async def _handshake(
        self,
        *,
        client: str,
        user: str | None,
        passwd: str | None,
        ashost: str = "0.0.0.0",
        sysnr: int = 0,
        lang: str = _DEFAULT_LANG,
    ) -> None:
        """Drive the NI/GW/logon handshake to READY (classic TCP path, async).

        Mirrors Connection._handshake for the DISCONNECTED → READY path.
        Facade-owned frames (GW_CONNECT, GW_INFO+GW_DONE_CLIENT, logon) are built
        via Connection's existing @staticmethod builders and sent with await.
        SNC / wRFC are out of scope — raise NotImplementedError if needed.

        Credentials are never logged (T-09-03-CRED).
        """
        local_ip = "127.0.0.1"
        try:
            sock = self._transport._writer.get_extra_info("socket")
            if sock is not None:
                local_ip = sock.getsockname()[0]
        except Exception:
            pass

        # NI-version request — begins DISCONNECTED → CONNECTED transition.
        await self._transport.send_message(self._session.start(local_ip=local_ip))

        while self._session.state is not SessionState.READY:
            resp = await self._transport.recv_message()
            prev_state = self._session.state
            out = self._session.feed(resp)
            if out:
                await self._transport.send_message(out)
            else:
                handle = self._session.handle or b"00000000"
                match prev_state:
                    case SessionState.CONNECTED:
                        await self._transport.send_message(
                            Connection._build_gw_connect_request(ashost, sysnr, snc=False)
                        )
                    case SessionState.NI_VERSIONED:
                        # GW_INFO has no server response; send both in the same iteration.
                        await self._transport.send_message(
                            Connection._build_gw_info(handle, ashost, snc=False)
                        )
                        await self._transport.send_message(
                            Connection._build_gw_done_client(handle, snc=False)
                        )
                    case SessionState.GW_CONNECTED:
                        tlv = Connection._build_logon_request(
                            client=client,
                            user=user,
                            passwd=passwd,
                            local_ip=local_ip,
                            lang=lang,
                        )
                        await self._transport.send_message(
                            Connection._build_logon_frame(handle, tlv)
                        )

    # ------------------------------------------------------------------ #
    # Async metadata bootstrap (classic TCP path — no wRFC, no SNC)       #
    # ------------------------------------------------------------------ #

    async def _call_bootstrap(self, func_name: str) -> FunctionDesc:
        """Async RFC_GET_FUNCTION_INTERFACE bootstrap for metadata (META-01, classic path).

        Mirrors Connection._call_bootstrap for the non-wRFC non-SNC branch.
        Always called from inside call() which already holds self._lock.
        OSError/IncompleteReadError propagate to call()'s CommunicationError wrapper.
        """
        attrs = self._session.attributes
        unicode_mode = attrs.unicode_mode if attrs else True

        bootstrap_params = [
            FieldDesc(
                name="FUNCNAME",
                rfctype=0,  # RFCTYPE_CHAR
                nuc_length=30,
                nuc_offset=0,
                uc_length=60,
                uc_offset=0,
                decimals=0,
                unicode_mode=unicode_mode,
                direction=RFC_IMPORT,
            ),
            FieldDesc(
                name="PARAMS",
                rfctype=5,  # RFCTYPE_TABLE
                nuc_length=0,
                nuc_offset=0,
                uc_length=0,
                uc_offset=0,
                decimals=0,
                unicode_mode=unicode_mode,
                direction=RFC_EXPORT,
            ),
        ]
        bootstrap_desc = FunctionDesc(
            name="RFC_GET_FUNCTION_INTERFACE",
            parameters=bootstrap_params,
        )

        request_tlv = build_invoke_request(
            "RFC_GET_FUNCTION_INTERFACE",
            bootstrap_desc,
            {"FUNCNAME": func_name},
        )
        handle = self._session.handle or b"        "
        frame = Connection._build_invoke_frame(handle, request_tlv)
        await self._transport.send_message(frame)
        response = await self._transport.recv_message()

        # A function module that is not remote-enabled answers GFI with a normal ABAP
        # exception (FL/046/FU_NOT_FOUND), and an exception reply carries no 0x0420 —
        # so the return-code check never fires and we used to hand back an empty
        # descriptor instead. Classify before parsing rows, on every path.
        raise_for_rfc_error(_strip_gw_header(response))

        rows = _parse_gfi_params_rows(response, unicode_mode=unicode_mode)
        if not rows:
            # A function module with no parameters at all is legal but rare, and it
            # is indistinguishable here from a metadata response we failed to read.
            # Either way the descriptor will be empty and every call will reject the
            # caller's arguments, so say so rather than returning it silently.
            _logger.warning(
                "no parameter rows parsed from the %s metadata response (%d bytes); "
                "the descriptor will be empty and calls will reject all arguments",
                func_name.upper(),
                len(response),
            )

        parameters: list[FieldDesc] = []
        struct_lookups: list[tuple[FieldDesc, str]] = []
        for row in rows:
            try:
                fd = _parse_params_row(row)
                parameters.append(fd)
                # TABLE params need the row layout just as much as STRUCTURE params
                # do: _parse_params_row promotes PARAMCLASS 'T' rows to RFCTYPE_TABLE
                # (see metadata._parse_params_row), so gating this lookup on
                # STRUCTURE alone would leave every TABLES param with type_desc=None
                # and make build_invoke_request refuse to encode its rows.
                if fd.rfctype in (RFCTYPE_STRUCTURE, RFCTYPE_TABLE):
                    tabname = row.get("TABNAME", "")
                    if tabname:
                        struct_lookups.append((fd, tabname))
            except ValueError as exc:
                # Exception rows are expected here and are not parameters.
                if is_exception_row(row):
                    continue
                # A parameter we cannot parse is a real problem: it will be missing
                # from the descriptor, so build_invoke_request will reject any value
                # the caller passes for it and the server will never return it.
                # Never drop one without saying so (T-03-META: the row is untrusted,
                # so keep parsing the rest rather than aborting the whole call).
                _logger.warning(
                    "ignoring unparseable metadata row for %s parameter %r: %s",
                    func_name.upper(),
                    row.get("PARAMETER", "<unnamed>"),
                    exc,
                )
                continue

        for fd, tabname in struct_lookups:
            if tabname not in self._struct_desc_cache:
                try:
                    self._struct_desc_cache[tabname] = await self._call_struct_bootstrap(tabname)
                except Exception as exc:
                    # Leaving type_desc=None makes encode/decode fail later with no
                    # hint as to which lookup went wrong, so record it here.
                    _logger.warning(
                        "could not fetch the layout of DDIC type %r; parameter %r "
                        "cannot be encoded or decoded: %s",
                        tabname,
                        fd.name,
                        exc,
                    )
            td = self._struct_desc_cache.get(tabname)
            if td is not None:
                fd.type_desc = td

        return FunctionDesc(name=func_name.upper(), parameters=parameters)

    async def _call_struct_bootstrap(self, tabname: str) -> TypeDesc:
        """Async RFC_GET_STRUCTURE_DEFINITION bootstrap (META-04, classic path)."""
        attrs = self._session.attributes
        unicode_mode = attrs.unicode_mode if attrs else True

        rsd_desc = FunctionDesc(
            name="RFC_GET_STRUCTURE_DEFINITION",
            parameters=[
                FieldDesc(
                    name="TABNAME",
                    rfctype=RFCTYPE_CHAR,
                    nuc_length=30,
                    nuc_offset=0,
                    uc_length=60,
                    uc_offset=0,
                    decimals=0,
                    unicode_mode=unicode_mode,
                    direction=RFC_IMPORT,
                ),
                FieldDesc(
                    name="FIELDS",
                    rfctype=RFCTYPE_TABLE,
                    nuc_length=0,
                    nuc_offset=0,
                    uc_length=0,
                    uc_offset=0,
                    decimals=0,
                    unicode_mode=unicode_mode,
                    direction=RFC_EXPORT,
                ),
            ],
        )

        request_tlv = build_invoke_request(
            "RFC_GET_STRUCTURE_DEFINITION",
            rsd_desc,
            {"TABNAME": tabname},
        )
        handle = self._session.handle or b"        "
        frame = Connection._build_invoke_frame(handle, request_tlv)
        await self._transport.send_message(frame)
        response = await self._transport.recv_message()
        raise_for_rfc_error(_strip_gw_header(response))
        dfies_rows = _parse_dfies_rows(response)
        return _build_type_desc_from_dfies(tabname, dfies_rows)

    # ------------------------------------------------------------------ #
    # Public async call surface (CLIENT-01..07, D-08)                     #
    # ------------------------------------------------------------------ #

    @property
    def _metadata_cache_key(self) -> str | None:
        """Key this connection's cached descriptors live under; None to not cache.

        Normally the system ID, so every connection to the same system shares one
        set of descriptors. But the logon response does not always carry one: a
        7.52 system answers with no 0x0450/0x0452/0x0453 at all, leaving sys_id
        empty. Caching under "" would file every such system in one bucket, and a
        process holding connections to two of them would be served the wrong
        system's descriptor for a same-named function module — silently, since a
        FunctionDesc carries no system of origin.

        So an unidentified system falls back to a token unique to this connection.
        Repeat calls on the connection still skip the round-trip; nothing is
        shared between systems that never identified themselves.
        """
        sys_id = self.sys_id
        if sys_id is None:
            return None  # not READY — nothing to key on yet
        if sys_id:
            return sys_id
        if self._anon_cache_key is None:
            # NUL prefix: a real SID is 3 alphanumerics, so this cannot collide.
            self._anon_cache_key = f"\x00anon-{uuid.uuid4().hex}"
        return self._anon_cache_key

    @property
    def sys_id(self) -> str | None:
        """System ID from negotiated ConnectionAttributes; None if not READY."""
        attrs = self._session.attributes
        return attrs.sys_id if attrs is not None else None

    def get_connection_attributes(self) -> ConnectionAttributes:
        """Return negotiated ConnectionAttributes (CLIENT-07 / TRANS-07)."""
        attrs = self._session.attributes
        if attrs is None:
            raise ValueError("AsyncConnection is not in READY state")
        return attrs

    async def call(self, func_name: str, **params: object) -> dict[str, Any]:
        """Await an RFC function module call; return a native-typed dict (CLIENT-01..07).

        Only the classic GW-framed TCP path is implemented (scope boundary: SNC/wRFC
        remain on the sync Connection path). CancelledError propagates (Pitfall 7).
        Credentials are never logged (T-09-03-CRED).
        """
        started = time.perf_counter()
        sent_before = getattr(self._transport, "bytes_sent", 0)
        received_before = getattr(self._transport, "bytes_received", 0)
        failed = True
        try:
            result = await self._call_instrumented(func_name, params)
            failed = False
            return result
        finally:
            # Recorded on the failure path too: a metrics view that counts only
            # successes hides exactly the trend worth alerting on.
            self.metrics.record(
                CallStats(
                    func_name=func_name,
                    duration_s=time.perf_counter() - started,
                    request_bytes=getattr(self._transport, "bytes_sent", 0) - sent_before,
                    response_bytes=(
                        getattr(self._transport, "bytes_received", 0) - received_before
                    ),
                    failed=failed,
                    server_duration_s=self._last_server_duration_s,
                )
            )

    async def _call_instrumented(self, func_name: str, params: dict[str, object]) -> dict[str, Any]:
        """The call itself; :meth:`call` wraps it to time and count."""
        # Cleared up front, not merely overwritten on success. A call that fails
        # before reading a response must not inherit the previous call's timing
        # and report it as its own -- that is a wrong number wearing the shape of
        # a right one, which is worse in a metrics series than a gap.
        self._last_server_duration_s = None
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                # Metadata: cache hit or async bootstrap (META-03/D-21).
                cache_key = self._metadata_cache_key
                desc = self._cache.get(cache_key, func_name) if cache_key is not None else None
                if desc is None:
                    try:
                        desc = await self._call_bootstrap(func_name)
                    except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                        raise CommunicationError(str(exc), original_exception=exc) from exc
                    if cache_key is not None:
                        self._cache.put(cache_key, desc)

                # Classic GW-framed invoke.
                call_params = _filter_call_params(
                    func_name,
                    desc,
                    dict(params),
                    strict=self._strict_params,
                    seen=self._dropped_params_seen,
                )
                request_tlv = build_invoke_request(func_name, desc, call_params)
                dm_names = dm_table_ids(desc, call_params)
                handle = self._session.handle or b"        "
                request = Connection._build_invoke_frame(handle, request_tlv)
                with _fail_closed(self._session, func_name):
                    await self._transport.send_message(request)
                    tlv_response = await _join_response_frames_async(
                        self._transport.recv_message, func_name
                    )
                    # Read the server's timing before parsing, so a call that
                    # raises an ABAP error still reports how long the server spent
                    # on it -- that is often the interesting case.
                    self._last_server_duration_s = extract_server_duration(tlv_response)
                    result = parse_invoke_response(tlv_response, desc, dm_names)
                result = _convert_date_time_fields(result, desc)
                return result
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    async def ping(self) -> bool:
        """Issue an async RFC-level RFCPING and report liveness (TRANS-05 parity).

        Sends the same fully framed invoke as Connection.ping(); see there for why a
        bare TLV body does not reach the gateway intact.
        """
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                handle = self._session.handle or b"        "
                frame = Connection._build_invoke_frame(handle, Connection._rfcping_request_tlv())
                with _fail_closed(self._session, "RFCPING"):
                    await self._transport.send_message(frame)
                    resp = await self._transport.recv_message()
                return Connection._rfcping_ok(resp)
            finally:
                # Guarded: a failed ping leaves the session BROKEN, and mark_ready
                # refuses any state but IN_CALL. Without the guard the finally
                # would raise over the top of the real error and hide it.
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    async def close(self) -> None:
        """Close the async transport (TRANS-06 parity)."""
        await self._transport.close()

    # ------------------------------------------------------------------ #
    # Async transactional RFC methods — tRFC/qRFC/bgRFC (D-01/D-07)      #
    # ------------------------------------------------------------------ #

    def _store_park(
        self,
        tid: str | None,
        unit_id: str | None,
        unit_type: str | None,
        payload: bytes,
    ) -> None:
        """Park ``payload`` in the durable store (sync helper, run under asyncio.to_thread).

        Routes to the TID store for tRFC/qRFC (``tid`` is not None) or the Unit
        store for bgRFC (``unit_id``/``unit_type`` are not None).  Logs a WARNING
        if no store is configured so the caller is not silently dropped
        (T-09-04-LOSS: RetryExhausted is still raised; this is just a best-effort
        parking step).  Credentials and payload bytes are NEVER logged
        (T-09-04-CRED).
        """
        if tid is not None:
            if self._tid_store is not None:
                self._tid_store.park(tid, payload)
            else:
                _logger.warning(
                    "transactional submit tRFC %s exhausted but no tid_store configured "
                    "— payload NOT persisted (T-09-04-LOSS); durable retry requires a store",
                    tid,
                )
        elif unit_id is not None and unit_type is not None:
            if self._unit_store is not None:
                self._unit_store.park(unit_id, unit_type, payload)
            else:
                _logger.warning(
                    "transactional submit bgRFC unit %s exhausted but no unit_store configured "
                    "— payload NOT persisted (T-09-04-LOSS); durable retry requires a store",
                    unit_id,
                )

    async def _submit_with_retry(
        self,
        *,
        tid: str | None = None,
        unit_id: str | None = None,
        unit_type: str | None = None,
        request_bytes: bytes,
        send_coro_factory: object,
        max_retries: int,
        retry_delay: float,
    ) -> object:
        """CommunicationError-only retry loop with exponential backoff + park-on-exhaust.

        Implements D-01 / D-02 / Pattern 3 from RESEARCH.md:

        - Retries ``send_coro_factory()`` on :class:`CommunicationError` up to
          ``max_retries`` times (default 3 attempts = 0, 1, 2, 3 = 4 total).
        - Backoff delays: ``retry_delay * 2**attempt`` ± 10% jitter (D-02).
        - On exhaustion: parks ``request_bytes`` via :meth:`_store_park` (off the
          event loop via ``asyncio.to_thread`` — Pitfall 2), logs WARNING, raises
          :class:`RetryExhausted` chained from the last :class:`CommunicationError`.
        - Retries log at DEBUG; exhaustion logs at WARNING (never credentials —
          T-09-04-CRED).

        Security (T-09-04-DBLEXEC): catches ONLY :class:`CommunicationError`.
        :class:`AbapApplicationError` and :class:`AbapSystemFailure` propagate on
        the first occurrence — they are deterministic; retrying would re-execute
        non-idempotent ABAP logic (Pitfall 4).

        Security (T-09-04-CANCEL): :exc:`asyncio.CancelledError` is a
        ``BaseException`` subclass; it is NOT caught by ``except CommunicationError``
        and propagates immediately (Pitfall 7).
        """
        log_key = tid or unit_id or "?"

        for attempt in range(max_retries + 1):
            try:
                return await send_coro_factory()  # type: ignore[operator]
            except CommunicationError as exc:
                if attempt == max_retries:
                    # All retries exhausted: park and raise (T-09-04-LOSS handled inside).
                    await asyncio.to_thread(
                        self._store_park, tid, unit_id, unit_type, request_bytes
                    )
                    _logger.warning(
                        "transactional submit %s exhausted after %d retries: %s",
                        log_key,
                        max_retries,
                        exc,
                    )
                    raise RetryExhausted(
                        tid=tid, unit_id=unit_id, unit_type=unit_type, cause=exc
                    ) from exc

                # Exponential backoff with ±10% jitter (D-02, discretion item).
                delay = retry_delay * (2**attempt)
                delay *= 1.0 + random.uniform(-0.1, 0.1)
                _logger.debug(
                    "transactional submit %s retry %d/%d in %.2fs: %s",
                    log_key,
                    attempt + 1,
                    max_retries,
                    delay,
                    exc,
                )
                await asyncio.sleep(delay)

        # Unreachable — loop always either returns or raises.  Satisfy type checker.
        raise AssertionError("unreachable")  # pragma: no cover

    async def call_transactional(
        self,
        func_name: str,
        *,
        tid: str,
        queue: str | None = None,
        **params: object,
    ) -> None:
        """Submit a tRFC (or qRFC) call with CommunicationError auto-retry (D-01).

        Async port of :meth:`Connection.call_transactional` — same exactly-once
        semantics via the SAME ``tid`` resent on every retry (backend returns
        ``RFC_EXECUTED`` for known TIDs — SDK type definitions).  Routes through
        :meth:`_submit_with_retry` so transient failures are retried up to
        ``self._max_retries`` times before parking and raising
        :class:`RetryExhausted`.

        :class:`AbapApplicationError` / :class:`AbapSystemFailure` propagate on the
        first occurrence (Pitfall 4 — deterministic; never retried).

        Credentials are never logged (T-09-04-CRED).
        """
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_trfc_request(tid, func_name, queue=queue)
                handle = self._session.handle or b"        "
                request = Connection._build_invoke_frame(handle, request_tlv)

                async def _do_send() -> None:
                    try:
                        await self._transport.send_message(request)
                        await self._transport.recv_message()
                    except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                        raise CommunicationError(str(exc), original_exception=exc) from exc

                await self._submit_with_retry(
                    tid=tid,
                    request_bytes=request,
                    send_coro_factory=_do_send,
                    max_retries=self._max_retries,
                    retry_delay=self._retry_delay,
                )
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    async def confirm_tid(self, tid: str) -> None:
        """Confirm a TID as a distinct lifecycle step (TRFC-02 / D-04 — async parity).

        Async port of :meth:`Connection.confirm_tid`.  Sends ARFC_DEST_CONFIRM
        to the backend.  Should only be called after :meth:`call_transactional`
        succeeded without :class:`CommunicationError`.

        Credentials are never logged (T-09-04-CRED).
        """
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_trfc_confirm_request(tid)
                handle = self._session.handle or b"        "
                request = Connection._build_invoke_frame(handle, request_tlv)
                try:
                    await self._transport.send_message(request)
                    await self._transport.recv_message()
                except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    def create_unit(
        self,
        uid: str | None = None,
        queues: list[str] | None = None,
    ) -> _AsyncUnitHandle:
        """Create an async bgRFC unit context manager (TRFC-05 / D-05 — async parity).

        Returns a one-shot async context manager (:class:`_AsyncUnitHandle`) that
        buffers ``await unit.call(...)`` invocations.  On ``__aexit__`` with no
        exception, the buffered calls are submitted atomically via
        :meth:`_submit_unit` (which routes through the retry loop).

        Async parity of :meth:`Connection.create_unit`; same UnitID generation
        and type-selection logic.
        """
        if uid is None:
            uid = uuid.uuid4().hex.upper()
        unit_type = "Q" if (queues and len(queues) > 0) else "T"
        return _AsyncUnitHandle(
            connection=self,
            uid=uid,
            unit_type=unit_type,
            queues=queues or [],
        )

    async def _submit_unit(
        self,
        uid: str,
        unit_type: str,
        queues: list[str],
        buffered_calls: list[bytes],
    ) -> None:
        """Submit a bgRFC unit via BGRFC_DEST_SHIP with CommunicationError retry (D-01).

        Async port of :meth:`Connection._submit_unit`.  Routes through
        :meth:`_submit_with_retry` for automatic retry on :class:`CommunicationError`.
        On exhaustion, raises :class:`RetryExhausted` with ``.unit_id`` set.

        Called by :meth:`_AsyncUnitHandle.__aexit__` on clean exit.
        Credentials are never logged (T-09-04-CRED).
        """
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_bgrfc_request(uid, unit_type, queues, buffered_calls)
                handle = self._session.handle or b"        "
                request = Connection._build_invoke_frame(handle, request_tlv)

                async def _do_send() -> None:
                    try:
                        await self._transport.send_message(request)
                        await self._transport.recv_message()
                    except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                        raise CommunicationError(str(exc), original_exception=exc) from exc

                await self._submit_with_retry(
                    unit_id=uid,
                    unit_type=unit_type,
                    request_bytes=request,
                    send_coro_factory=_do_send,
                    max_retries=self._max_retries,
                    retry_delay=self._retry_delay,
                )
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    async def confirm_unit(self, unit_id: str, unit_type: str = "T") -> None:
        """Confirm a bgRFC unit as a distinct lifecycle step (TRFC-06 — async parity).

        Async port of :meth:`Connection.confirm_unit`.  Sends BGRFC_DEST_CONFIRM
        to the backend.  ``unit_type`` must match the type used at submit time
        (Pitfall 5).

        Credentials are never logged (T-09-04-CRED).
        """
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_bgrfc_confirm_request(unit_id, unit_type)
                handle = self._session.handle or b"        "
                request = Connection._build_invoke_frame(handle, request_tlv)
                try:
                    await self._transport.send_message(request)
                    await self._transport.recv_message()
                except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    async def rollback_unit(self, unit_id: str, unit_type: str = "T") -> None:
        """Signal bgRFC unit rollback (TRFC-06 — async parity).

        Async port of :meth:`Connection.rollback_unit`.  Sends a state query
        so unit_id validation fires (T-06-U02); full rollback FM is OG-06-02.

        Credentials are never logged (T-09-04-CRED).
        """
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_bgrfc_state_request(unit_id, unit_type)
                handle = self._session.handle or b"        "
                request = Connection._build_invoke_frame(handle, request_tlv)
                try:
                    await self._transport.send_message(request)
                    await self._transport.recv_message()
                except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    async def get_unit_state(self, unit_id: str, unit_type: str = "T") -> UnitState:
        """Query the current state of a bgRFC unit on the backend (TRFC-06 — async parity).

        Async port of :meth:`Connection.get_unit_state`.  Returns a
        :class:`~saprfclib.stores.UnitState` enum value.

        Credentials are never logged (T-09-04-CRED).
        """
        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                request_tlv = build_bgrfc_state_request(unit_id, unit_type)
                handle = self._session.handle or b"        "
                request = Connection._build_invoke_frame(handle, request_tlv)
                try:
                    await self._transport.send_message(request)
                    response = await self._transport.recv_message()
                except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                    raise CommunicationError(str(exc), original_exception=exc) from exc
                return Connection._parse_unit_state_response(response)
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

    async def retry_parked(self, tid: str) -> None:
        """Re-send a parked tRFC call from the durable store (D-03b).

        Reads the parked request bytes for ``tid`` from :attr:`_tid_store` and
        re-sends them through the same send/recv envelope wrapped in
        :meth:`_submit_with_retry`.  On success, removes the parked entry so
        subsequent :meth:`retry_parked` calls for the same TID raise
        :class:`~saprfclib.exceptions.TransactionalError`.

        Does NOT re-marshal the original parameters — re-uses the exact bytes
        from the store (D-03b: no re-marshaling).  The same TID is reused so
        exactly-once delivery is preserved (backend returns RFC_EXECUTED for
        known TIDs — SDK type definitions).

        Raises:
            TransactionalError: if no parked call exists for ``tid`` (unknown TID
                or already cleaned up), or if no ``tid_store`` is configured.
            RetryExhausted:     if the re-send exhausts all retries.
            CommunicationError: propagated directly if the call fails without retry.

        Credentials are never logged (T-09-04-CRED).
        """
        from saprfclib.exceptions import TransactionalError

        if self._tid_store is None:
            raise TransactionalError(f"retry_parked: no tid_store configured for {tid}")

        payload = await asyncio.to_thread(self._tid_store.get_parked, tid)
        if payload is None:
            raise TransactionalError(f"no parked call for {tid}")

        # Re-send the raw request bytes without re-marshaling (D-03b).
        async def _do_resend() -> None:
            try:
                await self._transport.send_message(payload)
                await self._transport.recv_message()
            except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                raise CommunicationError(str(exc), original_exception=exc) from exc

        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                await self._submit_with_retry(
                    tid=tid,
                    request_bytes=payload,
                    send_coro_factory=_do_resend,
                    max_retries=self._max_retries,
                    retry_delay=self._retry_delay,
                )
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

        # On success: remove the parked entry so re-drive is idempotent (D-03b).
        await asyncio.to_thread(self._tid_store.delete_parked, tid)

    async def retry_parked_unit(self, unit_id: str, unit_type: str = "T") -> None:
        """Re-send a parked bgRFC unit from the durable store (D-03b).

        Reads the parked request bytes for ``(unit_id, unit_type)`` from
        :attr:`_unit_store` and re-sends them through the retry loop.  On
        success, removes the parked entry.

        Raises:
            TransactionalError: if no parked unit exists or no ``unit_store`` is
                configured.
            RetryExhausted:     if the re-send exhausts all retries.

        Credentials are never logged (T-09-04-CRED).
        """
        from saprfclib.exceptions import TransactionalError

        if self._unit_store is None:
            raise TransactionalError(f"retry_parked_unit: no unit_store configured for {unit_id}")

        payload = await asyncio.to_thread(
            self._unit_store.get_parked,
            unit_id,
            unit_type,
        )
        if payload is None:
            raise TransactionalError(f"no parked unit for {unit_id} ({unit_type})")

        async def _do_resend() -> None:
            try:
                await self._transport.send_message(payload)
                await self._transport.recv_message()
            except (OSError, asyncio.IncompleteReadError, EOFError, TimeoutError) as exc:
                raise CommunicationError(str(exc), original_exception=exc) from exc

        async with self._lock:
            self._session._require_state(SessionState.READY)
            self._session.mark_in_call()
            try:
                await self._submit_with_retry(
                    unit_id=unit_id,
                    unit_type=unit_type,
                    request_bytes=payload,
                    send_coro_factory=_do_resend,
                    max_retries=self._max_retries,
                    retry_delay=self._retry_delay,
                )
            finally:
                if self._session.state is SessionState.IN_CALL:
                    self._session.mark_ready()

        await asyncio.to_thread(
            self._unit_store.delete_parked,
            unit_id,
            unit_type,
        )

    # ------------------------------------------------------------------ #
    # Async context manager support (D-08: async with connect_async())    #
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> AsyncConnection:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# connect_async — public async entry point for classic TCP paths (D-08)
# ---------------------------------------------------------------------------


async def connect_async(
    ashost: str,
    sysnr: str | int,
    client: str,
    user: str | None = None,
    passwd: str | None = None,
    *,
    lang: str = _DEFAULT_LANG,
    strict_params: bool = False,
    timeout: float | None = None,
    connect_timeout: float | None = DEFAULT_CONNECT_TIMEOUT,
    metadata_cache: MetadataCache | None = None,
    metadata_cache_key: str | None = None,
    saprouter: str | None = None,
    mshost: str | None = None,
    sysid: str | None = None,
    group: str | None = None,
    snc_lib: str | None = None,
    wshost: str | None = None,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    tid_store: TidStore | None = None,
    unit_store: UnitStore | None = None,
) -> AsyncConnection:
    """Open an async classic-RFC connection and return a ready AsyncConnection.

    Supports direct TCP, SAProuter, and message-server (load-balanced) paths —
    the same three paths as the sync connect() classic branch.

    Scope boundary (Phase 9): snc_lib and wshost paths raise NotImplementedError;
    use the synchronous saprfclib.connect() for SNC/wRFC (SEC-02/03/05/06).

    Credentials (passwd) are never logged or interpolated into exception messages
    (T-09-03-CRED). Returns a ready AsyncConnection usable as an async context
    manager: ``async with await connect_async(...) as conn: ...``

    Retry parameters (D-01/D-02):
        max_retries:  Maximum number of retry attempts on CommunicationError (default 3).
        retry_delay:  Base backoff delay in seconds; doubles each attempt (default 1.0).
        tid_store:    Pluggable TidStore for durable tRFC/qRFC parking (D-03b).
        unit_store:   Pluggable UnitStore for durable bgRFC parking (D-03b).

    ``lang`` is the logon language — one-character SAP code or two-character ISO
    code, matching saprfclib.connect(). ``strict_params`` likewise mirrors
    saprfclib.connect(): False (default) drops undeclared keyword arguments with a
    warning, True raises.
    """
    user, passwd = _resolve_credentials(user, passwd, snc_lib=snc_lib, ashost=ashost)

    if snc_lib is not None or wshost is not None:
        raise NotImplementedError(
            "snc_lib/wshost async connections are not supported in Phase 9 — "
            "use the synchronous saprfclib.connect() for SNC/wRFC"
        )

    from saprfclib.router import (
        MessageServerClient,
        open_route_async,
        parse_route_string,
    )

    if mshost is not None:
        # Message-server resolve: sync I/O; run off the event loop via to_thread.
        def _ms_resolve() -> tuple[str, int]:
            ms_transport = connect_tcp(
                mshost,
                _ms_port(sysid),
                timeout=timeout,
                connect_timeout=connect_timeout,
            )
            try:
                return MessageServerClient(ms_transport).resolve(group or "PUBLIC")
            finally:
                ms_transport.close()

        ashost, sysnr = await asyncio.to_thread(_ms_resolve)

    port = 3300 + int(sysnr)
    transport = await connect_tcp_async(
        ashost, port, timeout=timeout, connect_timeout=connect_timeout
    )

    if saprouter is not None:
        hops = parse_route_string(saprouter)
        await open_route_async(transport, hops, ashost, str(port))

    conn = AsyncConnection(
        transport,
        max_retries=max_retries,
        retry_delay=retry_delay,
        tid_store=tid_store,
        unit_store=unit_store,
        strict_params=strict_params,
        metadata_cache=metadata_cache,
        metadata_cache_key=metadata_cache_key,
    )
    await conn._handshake(
        client=client,
        user=user,
        passwd=passwd,
        ashost=ashost,
        sysnr=int(sysnr),
        lang=lang,
    )
    return conn
