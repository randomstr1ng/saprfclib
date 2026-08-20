# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — RFC invoke TLV builder and response parser
#
# This module owns the request/response wire format for RFC function calls (D-20).
# It bridges the codec (value bytes) and the connection (transport seam):
#
#   tlv_record(tag, data) -> bytes
#       Full open+close TLV record builder. Every invoke record has a trailing
#       close tag (writeRfcIDEnd pattern). This is different from session._tlv
#       which emits open-only records — do NOT reuse session._tlv here (Pitfall 1).
#
#   build_invoke_request(func_name, desc, params) -> bytes
#       Builds the RFC invoke TLV payload (bytes from offset 80 onward, NOT the
#       GW header). Routing is direction-based: EXPORTING params get 0x0205 decls;
#       IMPORTING/CHANGING/TABLE params supplied by the caller get 0x0201+0x0203.
#
#   parse_invoke_response(resp, desc) -> dict
#       Walks the response TLV (mirror session._parse_tlv bounds discipline,
#       T-04-RESP), classifies errors via exception TLV tags, and returns a
#       native-typed dict via codec.decode per FieldDesc.
#
# Wire format sources:
#   - docs/protocol/framing.md §"TLV Record Format" + §"RFC Function Call Sequence"
#   - tests/golden/framing/stfc_connection_{request,response}.bin (live captures)
#   - tests/golden/framing/stfc_exception_response.bin (live exception capture)
#
# Security (threat T-04-RESP): bounds-check every TLV record before slicing.
# Security (threat T-04-CRED): passwd never logged; exception fields come only
# from server error TLV tags, never from credential tags.
from __future__ import annotations

import struct
from typing import Any

from saprfclib.codec import decode, encode
from saprfclib.compress import DecompressError, sapcompress_decompress
from saprfclib.exceptions import AbapApplicationError, AbapSystemFailure
from saprfclib.types import (
    RFC_CHANGING,
    RFC_EXPORT,
    RFC_IMPORT,
    RFC_TABLES,
    FieldDesc,
    FunctionDesc,
)

# rfctype constant for TABLE (RFCTYPE_TABLE = 5 from sapnwrfc.h / codec.py)
# BN-CONFIRMED: RfcParameter::rfcSerialize 0x4afdfe checks rcx_1 == 5 for TABLE branch
_RFCTYPE_TABLE = 5

__all__ = [
    "tlv_record",
    "build_invoke_request",
    "parse_invoke_response",
    "build_trfc_request",
    "build_trfc_confirm_request",
    "build_bgrfc_request",
    "build_bgrfc_confirm_request",
    "build_bgrfc_state_request",
]

# TLV tag constants (confirmed from golden fixtures + framing.md)
_TAG_CALL_START = 0x0502  # empty: RFC call-start marker
_TAG_RFC_VERSION = 0x000B  # RFC version string "754" UTF-16LE
_TAG_FUNC_NAME = 0x0102  # function name UTF-16LE
_TAG_PARAM_SECTION = 0x0512  # empty: parameter section start
_TAG_EXPORT_DECL = 0x0205  # EXPORTING param declaration (name UTF-16LE)
_TAG_PARAM_NAME = 0x0201  # IMPORTING/CHANGING/TABLE param name UTF-16LE
_TAG_PARAM_VALUE = 0x0203  # IMPORTING/CHANGING/TABLE param value (codec bytes)
_TAG_TERMINATOR = 0xFFFF  # stream terminator (len=0)

# Table protocol tags (BN-CONFIRMED from RfcParameter::rfcSerialize 0x4afdfe +
# RfcTable::rfcSerialize 0x4b3693 + writeRfcTableInfo 0x551860)
#
# 0x0301 is the TABLE NAME TAG — it carries the param name UTF-16LE as its value
# and replaces 0x0201 for rfctype==5 params.  There is NO separate empty "begin"
# marker before it.  REQUEST sequence:
#   0x0301(name) → [0x0330(dm_id)] → 0x0302(row_size+row_count) → 0x0303* → 0x0306
# RESPONSE sequence (server uses same rfcSerialize path — symmetric):
#   0x0301(name) → 0x0302(info) → {0x0303|0x0304|0x0305}* → 0x0306
_TAG_TABLE_NAME = 0x0301  # TABLE param name tag (replaces 0x0201 for TABLE rfctype)
_TAG_TABLE_BEGIN = 0x0301  # alias: same tag received in responses (name+begin combined)
_TAG_TABLE_INFO = 0x0302  # 8B: [0-3] BE uint32 row_size, [4-7] BE uint32 row_count
_TAG_TABLE_CONTENT = 0x0303  # uncompressed row data (RFCID_TableContent)
# BN-CONFIRMED (RfcConnectionBase::readUpTo 0x55662a case 3): 0x0304 (RFCID_TableCompr) is
# also raw row data — same rfcDeserialize path as 0x0303 despite the misleading name.
_TAG_TABLE_CONTENT_ALT = 0x0304  # raw row data, alternate tag (RFCID_TableCompr)
_TAG_TABLE_CONTENT_LZ = (
    0x0305  # SAPCOMPRESS compressed rows (RFCID_TableContLZ; rfcDeserializeCompressed)
)
_TAG_TABLE_END = 0x0306  # marks end of TABLE parameter stream
_TAG_DM_TABLE_ID = 0x0330  # 4B BE uint32 DM table tracking ID (getNextDMTableId counter)

# Response-only tags (confirmed from golden response fixture)
_TAG_RESPONSE_START = 0x0500  # empty: response start marker
_TAG_RETURN_CODE = 0x0420  # 4B BE uint32 return code (0=success)

# Exception-specific tags (confirmed from stfc_exception_response.bin)
_TAG_EXCEPTION_NUMBER = 0x0417  # exception sequence number UTF-16LE (e.g. "000")
_TAG_EXCEPTION_KEY = 0x0401  # ABAP exception key UTF-16LE (e.g. "EXAMPLE")
# Additional exception metadata tags (from sapnwrfc.h error TLV docs)
_TAG_EXCEPTION_MSG_CLASS = 0x0402
_TAG_EXCEPTION_MSG_TYPE = 0x0403
_TAG_EXCEPTION_MSG_NUMBER = 0x0404
_TAG_EXCEPTION_MSG_V1 = 0x0405
_TAG_EXCEPTION_MSG_V2 = 0x0406
_TAG_EXCEPTION_MSG_V3 = 0x0407
_TAG_EXCEPTION_MSG_V4 = 0x0408
_TAG_EXCEPTION_MESSAGE = 0x040B

# RFC version string (confirmed from golden fixture)
_RFC_VERSION = b"754"


# --------------------------------------------------------------------------- #
# Full-record TLV builder (open + close markers)
# --------------------------------------------------------------------------- #


def tlv_record(tag: int, data: bytes = b"") -> bytes:
    """Build one full-record TLV: [tag BE][len BE][data][tag BE].

    Uses the extended form (tag + 0xFFFF + ext-len 4B BE + data + tag) when
    len >= 0xFFFF (65535 bytes), per framing.md §"TLV Record Format"
    (writeRfcIDBegin 0x551560 / writeRfcIDEnd 0x5515da).

    This is NOT the same as session._tlv, which emits open-only records.
    Pitfall 1: session._tlv is insufficient for invoke — always use this function.
    """
    t = tag.to_bytes(2, "big")
    n = len(data)
    if n >= 0xFFFF:
        # Extended form: tag(2) + 0xFFFF(2) + ext_len(4 BE) + data + tag(2)
        return t + b"\xff\xff" + struct.pack(">I", n) + data + t
    # Normal form: tag(2) + len(2 BE) + data + tag(2)
    return t + n.to_bytes(2, "big") + data + t


# --------------------------------------------------------------------------- #
# Request builder
# --------------------------------------------------------------------------- #


def build_invoke_request(
    func_name: str,
    desc: FunctionDesc,
    params: dict[str, Any],
    *,
    version: bytes = _RFC_VERSION,
) -> bytes:
    """Build the RFC invoke TLV payload (from offset 80 onward, NOT the GW header).

    TLV order (framing.md §"RFC Function Call Sequence", confirmed from golden fixture +
    BN RE of RfcFunction::rfcSerializeParams 0x4aef92):
      0x0502 empty: call-start
      0x000b UTF-16LE version string (default "754")
      0x0102 UTF-16LE function name
      0x0512 empty: param section start
      0x0205 per EXPORTING/CHANGING/TABLES param: param name UTF-16LE
             (rfcSupplyOutParam path: bit 1 set in direction → server returns this)
      0x0201 + 0x0203 per supplied IMPORTING/CHANGING scalar param: name + encoded value
      0x0301 + {0x0330 + 0x0302 + 0x0303* + 0x0306} per supplied TABLE param with rows
             (0x0301 carries the param name; 0x0330 = DM table ID counter)
      0xFFFF empty: terminator

    Direction routing (Pitfall 3: caller perspective, BN-CONFIRMED):
      RFC_EXPORT (0x02): ABAP EXPORTING → server sends back → 0x0205 decl only
      RFC_IMPORT (0x01): ABAP IMPORTING → caller sends → 0x0201+0x0203 (scalar/struct)
      RFC_CHANGING (0x03): caller sends AND receives → 0x0205 decl + 0x0201+0x0203 value
      RFC_TABLES (0x07): tables → 0x0205 decl + 0x0301+table protocol if rows supplied

    TABLE protocol (BN-CONFIRMED from RfcParameter::rfcSerialize 0x4afdfe +
    RfcTable::rfcSerialize 0x4b3693 + writeRfcTableInfo 0x551860):
      - 0x0301 tag carries the param name (replaces 0x0201 for rfctype==5)
      - 0x0330: 4B BE DM table ID (internal per-call counter starting at 1)
      - 0x0302: 8B [BE uint32 row_size][BE uint32 row_count]
      - 0x0303 per row: flat encoded row bytes
      - 0x0306: end of table
      Empty tables: 0x0205 decl only (no 0x0301+data block)

    Param values are encoded via codec.encode(rfctype, value, field) — Pitfall 2:
    let the codec handle UTF-16 length math (code units, not chars).
    """
    # Encode version string as UTF-16LE (confirmed from golden fixture: b"754" -> 37 00 35 00 34 00)
    if isinstance(version, str):
        version_bytes = version.encode("utf-16-le")
    else:
        version_bytes = version.decode("ascii").encode("utf-16-le")
    parts: list[bytes] = [
        tlv_record(_TAG_CALL_START),
        tlv_record(_TAG_RFC_VERSION, version_bytes),
        tlv_record(_TAG_FUNC_NAME, func_name.encode("utf-16-le")),
        tlv_record(_TAG_PARAM_SECTION),
    ]

    # Emit 0x0205 decls for params the server should return (EXPORT, CHANGING, TABLES).
    # BN: rfcSupplyOutParam at 0x4b01e2 — direction bit 1 set (0x02, 0x03, 0x07) triggers this.
    for field in desc.parameters:
        if field.direction in (RFC_EXPORT, RFC_CHANGING, RFC_TABLES):
            parts.append(tlv_record(_TAG_EXPORT_DECL, field.name.encode("utf-16-le")))

    # Emit param values for caller-supplied IMPORTING/CHANGING/TABLES params.
    params_upper = {k.upper(): v for k, v in params.items()}
    _dm_id = 0  # per-call DM table ID counter (getNextDMTableId equivalent)
    for field in desc.parameters:
        if field.direction == RFC_EXPORT:
            continue  # server fills EXPORT params; we only declare, not supply data
        name_upper = field.name.upper()
        if name_upper not in params_upper:
            continue  # optional param not supplied by caller — skip
        value = params_upper[name_upper]

        if field.rfctype == _RFCTYPE_TABLE:
            # TABLE protocol: 0x0301(name) + 0x0330(dm_id) + 0x0302(info) + 0x0303*(rows) + 0x0306
            # Empty tables: 0x0205 decl (already emitted above) suffices; no 0x0301 block.
            rows: list[Any] = value if value else []
            if not rows:
                continue
            assert field.type_desc is not None, (
                f"TABLE param {field.name!r} has no type_desc — cannot encode rows"
            )
            all_row_bytes = encode(_RFCTYPE_TABLE, rows, field)
            row_size = field.type_desc.uc_size if field.unicode_mode else field.type_desc.nuc_size
            row_count = len(rows)
            _dm_id += 1
            parts.append(tlv_record(_TAG_TABLE_NAME, field.name.encode("utf-16-le")))
            parts.append(tlv_record(_TAG_DM_TABLE_ID, struct.pack(">I", _dm_id)))
            parts.append(tlv_record(_TAG_TABLE_INFO, struct.pack(">II", row_size, row_count)))
            for i in range(row_count):
                row_slice = all_row_bytes[i * row_size : (i + 1) * row_size]
                parts.append(tlv_record(_TAG_TABLE_CONTENT, row_slice))
            parts.append(tlv_record(_TAG_TABLE_END))
        else:
            # Scalar / structure: 0x0201(name) + 0x0203(value)
            encoded = encode(field.rfctype, value, field)
            parts.append(tlv_record(_TAG_PARAM_NAME, field.name.encode("utf-16-le")))
            parts.append(tlv_record(_TAG_PARAM_VALUE, encoded))

    # Terminator: tag(2) + len(2) + close_tag(2) — confirmed from golden fixture
    parts.append(tlv_record(_TAG_TERMINATOR))

    return b"".join(parts)


# --------------------------------------------------------------------------- #
# tRFC / qRFC request builders (TRFC-01, TRFC-02, TRFC-04)
# --------------------------------------------------------------------------- #
#
# BN-CONFIRMED (Plan 06-01): tRFC and qRFC are ordinary synchronous RFC calls
# to the SAP system function module ARFC_DEST_SHIP.  There are NO new TLV tags
# for the call-type discriminator — the function name in TLV 0x0102 IS the
# discriminator (RfcServer::dispatch 0x4bb5de).  The TID is carried as a CHAR
# parameter (ARFCTID) within the ARFCSSTATE table, encoded UTF-16LE exactly
# like any other CHAR param.  The queue name is carried similarly for qRFC.
#
# OG-06-01 CONFIRMED (2026-08-05): test_live_qrfc_queued_call passed — named-param
# encoding (ARFCTID/ARFCFNAM/ARFCQUEUE as CHAR params) confirmed correct by live qRFC
# gate.  No raw ARFCSSTATE struct decomposition (ARFCIPID/ARFCPID/ARFCTIME/ARFCTIDCNT)
# needed — server reads only the named params.
#
# Anti-pattern avoided: this module does NOT define a second TLV writer.  Both
# functions use the existing `tlv_record()` primitive only.
#
# Security (T-06-C02): TID length is enforced to exactly RFC_TID_LN=24 chars
# before encoding.  Queue name is bounded to the protocol max (256 chars).

_TID_LN = 24  # RFC_TID_LN from sapnwrfc.h:79
_MAX_QUEUE_NAME = 256  # conservative upper bound (sapnwrfc.h §RFC_MAX_QUEUE_NAME_LENGTH)

# TID character alphabet confirmed by BN RfcTransaction::createTid 0x4b5a33.
_TID_ALPHABET: frozenset[str] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-")

# System FM names (BN RfcServer::dispatch 0x4bb5de / 0x4bb65a).
_ARFC_DEST_SHIP = "ARFC_DEST_SHIP"
_ARFC_DEST_CONFIRM = "ARFC_DEST_CONFIRM"


def _validate_tid(tid: str) -> None:
    """Raise ValueError if tid is not a valid 24-char TID (T-06-C02 / V5).

    TID must be exactly RFC_TID_LN (24) characters from the BN-confirmed alphabet
    ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-.  A UUID-hex TID (uppercase, digits
    only) is a valid subset and accepted.

    Source: sapnwrfc.h:79 (RFC_TID_LN=24), BN 0x4b5a33 (alphabet).
    """
    if not isinstance(tid, str):
        raise ValueError(f"TID must be a str, got {type(tid).__name__!r}")
    if len(tid) != _TID_LN:
        raise ValueError(f"TID must be exactly {_TID_LN} characters (RFC_TID_LN); got {len(tid)}")
    bad = [c for c in tid if c not in _TID_ALPHABET]
    if bad:
        raise ValueError(
            f"TID contains characters not in the RFC alphabet: {bad!r} "
            f"(BN 0x4b5a33 — ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-)"
        )


def _validate_queue_name(queue: str) -> None:
    """Raise ValueError if queue name is empty or exceeds the protocol maximum."""
    if not queue:
        raise ValueError("queue name must not be empty")
    if len(queue) > _MAX_QUEUE_NAME:
        raise ValueError(f"queue name too long ({len(queue)} chars; max {_MAX_QUEUE_NAME})")


def build_trfc_request(
    tid: str,
    func_name: str,
    *,
    queue: str | None = None,
    version: bytes = _RFC_VERSION,
) -> bytes:
    """Build the RFC invoke TLV payload for an ARFC_DEST_SHIP (tRFC/qRFC) call.

    This is a standard invoke frame with function name ARFC_DEST_SHIP in TLV
    0x0102 (the call-type discriminator per BN 0x4bb5de).  The TID and the
    wrapped function name are encoded as named CHAR parameters (UTF-16LE).

    For qRFC (queue is not None): the queue name is included as an additional
    CHAR parameter (ARFCQUEUE) so the server can read the queue indicator at
    ARFCSSTATE offset 0xe58 (BN 0x4bb632).

    Security: validates TID length and alphabet, queue name length before encoding
    (T-06-C02 / RESEARCH V5).

    OG-06-01 CONFIRMED (2026-08-05): named-param encoding confirmed via live qRFC gate.
    TID as ARFCTID param works; no raw ARFCSSTATE field decomposition needed.

    Args:
        tid:       24-char TID from the RFC TID alphabet (BN 0x4b5a33).
        func_name: The wrapped ABAP function module name (informational; stored as
                   ARFCFNAM in ARFCSSTATE — included as ARFCFNAM param for now).
        queue:     qRFC queue name; when not None, the call is qRFC.
        version:   RFC version string bytes (default b"754").

    Returns:
        Raw TLV payload bytes (not the full GW frame — pass to
        ``Connection._build_invoke_frame``).
    """
    _validate_tid(tid)
    if queue is not None:
        _validate_queue_name(queue)

    version_bytes: bytes
    if isinstance(version, str):
        version_bytes = version.encode("utf-16-le")
    else:
        version_bytes = version.decode("ascii").encode("utf-16-le")

    parts: list[bytes] = [
        tlv_record(_TAG_CALL_START),
        tlv_record(_TAG_RFC_VERSION, version_bytes),
        tlv_record(_TAG_FUNC_NAME, _ARFC_DEST_SHIP.encode("utf-16-le")),
        tlv_record(_TAG_PARAM_SECTION),
        # TID parameter — 24 chars → 48 bytes UTF-16LE (Pitfall 4)
        tlv_record(_TAG_PARAM_NAME, "ARFCTID".encode("utf-16-le")),
        tlv_record(_TAG_PARAM_VALUE, tid.encode("utf-16-le")),
        # Wrapped FM name — informational (part of ARFCSSTATE.ARFCFNAM)
        tlv_record(_TAG_PARAM_NAME, "ARFCFNAM".encode("utf-16-le")),
        tlv_record(_TAG_PARAM_VALUE, func_name.encode("utf-16-le")),
    ]
    if queue is not None:
        # qRFC: include queue name so server sees non-zero at ARFCSSTATE+0xe58.
        parts.append(tlv_record(_TAG_PARAM_NAME, "ARFCQUEUE".encode("utf-16-le")))
        parts.append(tlv_record(_TAG_PARAM_VALUE, queue.encode("utf-16-le")))
    parts.append(tlv_record(_TAG_TERMINATOR))
    return b"".join(parts)


def build_trfc_confirm_request(
    tid: str,
    *,
    version: bytes = _RFC_VERSION,
) -> bytes:
    """Build the RFC invoke TLV payload for an ARFC_DEST_CONFIRM call.

    Confirms the TID on the backend, allowing the server to remove it from
    ARFCRSTATE.  After this call the backend loses duplicate-execution protection
    for this TID (sapnwrfc.h:2168 — never call before verifying the submit landed).

    Security: validates TID before encoding (T-06-C02).

    BN source: RfcServer::dispatch 0x4bb65a (ARFC_DEST_CONFIRM branch).
    """
    _validate_tid(tid)

    version_bytes: bytes
    if isinstance(version, str):
        version_bytes = version.encode("utf-16-le")
    else:
        version_bytes = version.decode("ascii").encode("utf-16-le")

    return b"".join(
        [
            tlv_record(_TAG_CALL_START),
            tlv_record(_TAG_RFC_VERSION, version_bytes),
            tlv_record(_TAG_FUNC_NAME, _ARFC_DEST_CONFIRM.encode("utf-16-le")),
            tlv_record(_TAG_PARAM_SECTION),
            tlv_record(_TAG_PARAM_NAME, "ARFCTID".encode("utf-16-le")),
            tlv_record(_TAG_PARAM_VALUE, tid.encode("utf-16-le")),
            tlv_record(_TAG_TERMINATOR),
        ]
    )


# --------------------------------------------------------------------------- #
# bgRFC request builders (TRFC-05, TRFC-06)
# --------------------------------------------------------------------------- #
#
# BN-CONFIRMED (Plan 06-01): bgRFC uses BGRFC_DEST_SHIP / BGRFC_DEST_CONFIRM /
# BGRFC_CHECK_UNIT_STATE_SERVER function-module names (RfcServer::dispatch 0x4bb5de).
# The UnitID is a 32-char uppercase hex string (BN 0x511855: pfuuid_print asserts
# len == 32).  Unit type is 'T' (no queues) or 'Q' (queues given) — BN 0x483919.
#
# OG-06-02 CONFIRMED (2026-08-05): test_live_bgrfc_unit_lifecycle passed — BGRFC_UNIT_ID/
# BGRFC_UNIT_TYPE named-param encoding confirmed correct by live bgRFC gate.  No raw
# BGRFC_SRV_STATE/ARFCSDATA struct layout needed — server reads only the named params.
# Source: BN 0x4bb6b1 discriminator + live bgRFC gate.
#
# Security (T-06-U02): UnitID length is enforced to exactly RFC_UNITID_LN=32 hex chars
# before encoding. queue_names are bounded.

_UNITID_LN = 32  # RFC_UNITID_LN from sapnwrfc.h:80
_UNITID_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# System FM names (BN RfcServer::dispatch 0x4bb5de / 0x4bb6b1 / 0x4bb713 / 0x4bb733).
_BGRFC_DEST_SHIP = "BGRFC_DEST_SHIP"
_BGRFC_DEST_CONFIRM = "BGRFC_DEST_CONFIRM"
_BGRFC_CHECK_UNIT_STATE_SERVER = "BGRFC_CHECK_UNIT_STATE_SERVER"

# Unit type bytes: 'T' (0x54) = no queues; 'Q' (0x51) = queues given (BN 0x483919).
_UNIT_TYPE_T = "T"
_UNIT_TYPE_Q = "Q"


def _validate_unit_id(uid: str) -> None:
    """Raise ValueError if uid is not a valid 32-char uppercase hex UnitID (T-06-U02 / V5).

    UnitID must be exactly RFC_UNITID_LN (32) characters of uppercase hex (0-9A-F).
    Source: sapnwrfc.h:80 (RFC_UNITID_LN=32), BN 0x511855 (pfuuid_print → 32 hex chars).
    """
    if not isinstance(uid, str):
        raise ValueError(f"UnitID must be a str, got {type(uid).__name__!r}")
    if len(uid) != _UNITID_LN:
        raise ValueError(
            f"UnitID must be exactly {_UNITID_LN} characters (RFC_UNITID_LN); got {len(uid)}"
        )
    bad = [c for c in uid if c not in _UNITID_CHARSET]
    if bad:
        raise ValueError(
            f"UnitID contains characters not in uppercase hex alphabet: {bad!r} "
            f"(BN 0x511855 — 0-9A-F only)"
        )


def build_bgrfc_request(
    unit_id: str,
    unit_type: str,
    queue_names: list[str],
    buffered_calls: list[bytes] | None = None,
    *,
    version: bytes = _RFC_VERSION,
) -> bytes:
    """Build the RFC invoke TLV payload for a BGRFC_DEST_SHIP (bgRFC submit) call.

    This is a standard invoke frame with function name BGRFC_DEST_SHIP in TLV
    0x0102 (the call-type discriminator per BN 0x4bb6b1). The UnitID and
    unit_type are encoded as named CHAR parameters (UTF-16LE).

    Open gap OG-06-02: the exact BGRFC_DEST_SHIP parameter byte layout is deferred
    to the D-08 live-capture gate. UnitID and unit_type are encoded as standalone
    CHAR params (BGRFC_UNIT_ID, BGRFC_UNIT_TYPE) until the exact structure is known.

    Security: validates UnitID length and hex charset before encoding (T-06-U02 / V5).

    Args:
        unit_id:        32-char uppercase hex UnitID (BN 0x511855).
        unit_type:      'T' (no queues) or 'Q' (queues given) — BN 0x483919.
        queue_names:    List of queue names (empty for type 'T').
        buffered_calls: Optional list of pre-serialized call TLV bytes to embed.
        version:        RFC version string bytes (default b"754").

    Returns:
        Raw TLV payload bytes (not the full GW frame).
    """
    _validate_unit_id(unit_id)
    if unit_type not in (_UNIT_TYPE_T, _UNIT_TYPE_Q):
        raise ValueError(f"unit_type must be 'T' or 'Q', got {unit_type!r} (BN 0x483919)")

    version_bytes: bytes
    if isinstance(version, str):
        version_bytes = version.encode("utf-16-le")
    else:
        version_bytes = version.decode("ascii").encode("utf-16-le")

    parts: list[bytes] = [
        tlv_record(_TAG_CALL_START),
        tlv_record(_TAG_RFC_VERSION, version_bytes),
        tlv_record(_TAG_FUNC_NAME, _BGRFC_DEST_SHIP.encode("utf-16-le")),
        tlv_record(_TAG_PARAM_SECTION),
        # UnitID — 32 chars → 64 bytes UTF-16LE (Pitfall 4: 2 bytes per code unit)
        tlv_record(_TAG_PARAM_NAME, "BGRFC_UNIT_ID".encode("utf-16-le")),
        tlv_record(_TAG_PARAM_VALUE, unit_id.encode("utf-16-le")),
        # Unit type — 'T' or 'Q' (BN 0x483919)
        tlv_record(_TAG_PARAM_NAME, "BGRFC_UNIT_TYPE".encode("utf-16-le")),
        tlv_record(_TAG_PARAM_VALUE, unit_type.encode("utf-16-le")),
    ]
    # Embed queue names (one param per queue — informational until OG-06-02 resolved).
    for i, qname in enumerate(queue_names):
        if qname:
            parts.append(tlv_record(_TAG_PARAM_NAME, f"BGRFC_QUEUE_{i}".encode("utf-16-le")))
            parts.append(tlv_record(_TAG_PARAM_VALUE, qname.encode("utf-16-le")))
    # Embed buffered call payloads (each is a serialized TLV fragment from unit.call).
    if buffered_calls:
        # Encode the count so the server knows how many calls to expect
        parts.append(tlv_record(_TAG_PARAM_NAME, "BGRFC_CALL_COUNT".encode("utf-16-le")))
        parts.append(tlv_record(_TAG_PARAM_VALUE, str(len(buffered_calls)).encode("utf-16-le")))
        for idx, call_bytes in enumerate(buffered_calls):
            # Each buffered call is its own TLV payload embedded as raw bytes
            parts.append(tlv_record(_TAG_PARAM_NAME, f"BGRFC_CALL_{idx}".encode("utf-16-le")))
            parts.append(tlv_record(_TAG_PARAM_VALUE, call_bytes))
    parts.append(tlv_record(_TAG_TERMINATOR))
    return b"".join(parts)


def build_bgrfc_confirm_request(
    unit_id: str,
    unit_type: str,
    *,
    version: bytes = _RFC_VERSION,
) -> bytes:
    """Build the RFC invoke TLV payload for a BGRFC_DEST_CONFIRM call.

    Confirms the Unit on the backend, allowing status cleanup.

    Security: validates UnitID before encoding (T-06-U02).

    BN source: RfcServer::dispatch 0x4bb713 (BGRFC_DEST_CONFIRM branch).
    """
    _validate_unit_id(unit_id)
    if unit_type not in (_UNIT_TYPE_T, _UNIT_TYPE_Q):
        raise ValueError(f"unit_type must be 'T' or 'Q', got {unit_type!r}")

    version_bytes: bytes
    if isinstance(version, str):
        version_bytes = version.encode("utf-16-le")
    else:
        version_bytes = version.decode("ascii").encode("utf-16-le")

    return b"".join(
        [
            tlv_record(_TAG_CALL_START),
            tlv_record(_TAG_RFC_VERSION, version_bytes),
            tlv_record(_TAG_FUNC_NAME, _BGRFC_DEST_CONFIRM.encode("utf-16-le")),
            tlv_record(_TAG_PARAM_SECTION),
            tlv_record(_TAG_PARAM_NAME, "BGRFC_UNIT_ID".encode("utf-16-le")),
            tlv_record(_TAG_PARAM_VALUE, unit_id.encode("utf-16-le")),
            tlv_record(_TAG_PARAM_NAME, "BGRFC_UNIT_TYPE".encode("utf-16-le")),
            tlv_record(_TAG_PARAM_VALUE, unit_type.encode("utf-16-le")),
            tlv_record(_TAG_TERMINATOR),
        ]
    )


def build_bgrfc_state_request(
    unit_id: str,
    unit_type: str,
    *,
    version: bytes = _RFC_VERSION,
) -> bytes:
    """Build the RFC invoke TLV payload for a BGRFC_CHECK_UNIT_STATE_SERVER call.

    Queries the current Unit state on the backend, returning a UnitState.

    Security: validates UnitID before encoding (T-06-U02).

    BN source: RfcServer::dispatch 0x4bb733 (BGRFC_CHECK_UNIT_STATE_SERVER branch).
    """
    _validate_unit_id(unit_id)
    if unit_type not in (_UNIT_TYPE_T, _UNIT_TYPE_Q):
        raise ValueError(f"unit_type must be 'T' or 'Q', got {unit_type!r}")

    version_bytes: bytes
    if isinstance(version, str):
        version_bytes = version.encode("utf-16-le")
    else:
        version_bytes = version.decode("ascii").encode("utf-16-le")

    return b"".join(
        [
            tlv_record(_TAG_CALL_START),
            tlv_record(_TAG_RFC_VERSION, version_bytes),
            tlv_record(_TAG_FUNC_NAME, _BGRFC_CHECK_UNIT_STATE_SERVER.encode("utf-16-le")),
            tlv_record(_TAG_PARAM_SECTION),
            tlv_record(_TAG_PARAM_NAME, "BGRFC_UNIT_ID".encode("utf-16-le")),
            tlv_record(_TAG_PARAM_VALUE, unit_id.encode("utf-16-le")),
            tlv_record(_TAG_PARAM_NAME, "BGRFC_UNIT_TYPE".encode("utf-16-le")),
            tlv_record(_TAG_PARAM_VALUE, unit_type.encode("utf-16-le")),
            tlv_record(_TAG_TERMINATOR),
        ]
    )


# --------------------------------------------------------------------------- #
# Response parser
# --------------------------------------------------------------------------- #


def parse_invoke_response(resp: bytes, desc: FunctionDesc) -> dict[str, Any]:
    """Parse a RFC invoke response TLV stream and return a native-typed dict.

    Walks the TLV stream with bounds-checking (T-04-RESP, mirrors session._parse_tlv).
    Classification logic (confirmed from stfc_exception_response.bin golden fixture):
      - Tag 0x0417 present → AbapApplicationError (ABAP exception)
      - Tag 0x0420 non-zero and no exception tags → AbapSystemFailure
      - Tag 0x0420 == 0 → success; walk 0x0201/0x0203 pairs and decode values

    Pitfall 4: 0x0420 return code is 4B BE uint32 (use struct.unpack('>I')).
    Pitfall 2: value bytes from 0x0203 are passed directly to codec.decode — let
    the codec handle type-specific length/encoding (UTF-16 code-unit math, BCD, etc.).
    """
    tags = _parse_tlv_stream(resp)

    # --- Exception classification ---
    # AbapApplicationError: signaled by 0x0417 exception number tag (from live fixture).
    if _TAG_EXCEPTION_NUMBER in tags:
        key = _decode_utf16le(tags.get(_TAG_EXCEPTION_KEY))
        msg_class = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_CLASS))
        msg_type = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_TYPE))
        msg_number = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_NUMBER))
        msg_v1 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V1))
        msg_v2 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V2))
        msg_v3 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V3))
        msg_v4 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V4))
        message = _decode_utf16le(tags.get(_TAG_EXCEPTION_MESSAGE))
        raise AbapApplicationError(
            key=key or None,
            msg_class=msg_class or None,
            msg_type=msg_type or None,
            msg_number=msg_number or None,
            msg_v1=msg_v1 or None,
            msg_v2=msg_v2 or None,
            msg_v3=msg_v3 or None,
            msg_v4=msg_v4 or None,
            message=message or None,
        )

    # Return-code check (Pitfall 4: 4B BE uint32).
    rc_bytes = tags.get(_TAG_RETURN_CODE)
    if rc_bytes is not None:
        if len(rc_bytes) != 4:
            raise ValueError(f"return-code TLV 0x0420 has length {len(rc_bytes)}, expected 4")
        rc = struct.unpack(">I", rc_bytes)[0]
        if rc != 0:
            # Non-zero rc without an exception-key tag → system failure
            msg_class = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_CLASS))
            msg_type = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_TYPE))
            msg_number = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_NUMBER))
            msg_v1 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V1))
            msg_v2 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V2))
            msg_v3 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V3))
            msg_v4 = _decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V4))
            message = _decode_utf16le(tags.get(_TAG_EXCEPTION_MESSAGE))
            raise AbapSystemFailure(
                msg_class=msg_class or None,
                msg_type=msg_type or None,
                msg_number=msg_number or None,
                msg_v1=msg_v1 or None,
                msg_v2=msg_v2 or None,
                msg_v3=msg_v3 or None,
                msg_v4=msg_v4 or None,
                message=message or f"RFC return code {rc}",
            )

    # --- Success path: extract 0x0201/0x0203 value pairs ---
    # Build a name→FieldDesc map for EXPORTING params (server → caller).
    # CHANGING params also appear in the response (same direction as EXPORTING at
    # response boundary).
    param_map: dict[str, FieldDesc] = {}
    for field in desc.parameters:
        if field.direction != RFC_IMPORT:  # EXPORT, CHANGING, TABLES all come back
            param_map[field.name.upper()] = field

    result: dict[str, object] = {}
    # Walk the ordered tag list to pick up 0x0201+0x0203 pairs
    for name, value in _extract_name_value_pairs(resp):
        name_upper = name.upper()
        match_field: FieldDesc | None = param_map.get(name_upper)
        if match_field is None:
            continue  # unknown param name — ignore (defensive)
        result[match_field.name] = decode(match_field.rfctype, value, match_field)

    return result


# --------------------------------------------------------------------------- #
# TLV parsing helpers
# --------------------------------------------------------------------------- #


def _parse_tlv_stream(data: bytes) -> dict[int, bytes]:
    """Parse TLV stream into {tag: value} dict (last value wins for repeated tags).

    Bounds-checks every record against the remaining buffer (T-04-RESP, mirrors
    session._parse_tlv pattern from session.py). Extended form (len=0xFFFF + 4B
    ext_len) and repeated-tag suffix (session._parse_tlv pattern) are both handled.

    Raises ValueError if any record's claimed length exceeds the buffer.
    """
    out: dict[int, bytes] = {}
    pos = 0
    n = len(data)
    while pos + 4 <= n:
        tag = struct.unpack_from(">H", data, pos)[0]
        length = struct.unpack_from(">H", data, pos + 2)[0]
        pos += 4
        if tag == _TAG_TERMINATOR:
            break
        if length == 0xFFFF:
            # Extended form: 4B BE ext_len follows
            if pos + 4 > n:
                raise ValueError(
                    f"malformed TLV: tag 0x{tag:04x} extended form but buffer "
                    f"too short for ext_len field (pos={pos}, remaining={n - pos})"
                )
            ext_len = struct.unpack_from(">I", data, pos)[0]
            pos += 4
            end = pos + ext_len
            if end > n:
                raise ValueError(
                    f"malformed TLV: tag 0x{tag:04x} extended length {ext_len} "
                    f"exceeds remaining payload ({n - pos} bytes)"
                )
            out[tag] = data[pos:end]
            pos = end
        else:
            end = pos + length
            if end > n:
                raise ValueError(
                    f"malformed TLV: tag 0x{tag:04x} length {length} "
                    f"exceeds remaining payload ({n - pos} bytes)"
                )
            out[tag] = data[pos:end]
            pos = end
        # Skip the optional repeated-tag close suffix (extended TLV pattern).
        if pos + 2 <= n and struct.unpack_from(">H", data, pos)[0] == tag:
            pos += 2
    return out


def _extract_name_value_pairs(data: bytes) -> list[tuple[str, bytes]]:
    """Walk TLV stream and return ordered (name_str, value_bytes) pairs.

    Handles both scalar params and TABLE params:

    Scalar: 0x0201(name) → 0x0203(value)

    TABLE (BN-CONFIRMED from RfcParameter::rfcSerialize 0x4afdfe):
      0x0301(name)  ← combined name+begin; value is param name UTF-16LE
      0x0302(info)  ← 8B [BE row_size][BE row_count] (informational; ignored here)
      {0x0303|0x0304|0x0305}* rows  ← uncompressed or SAPCOMPRESS compressed
      0x0306(end)   ← yields (name, concatenated_row_bytes) pair

    For TABLE params the yielded value is concatenated flat row bytes
    (uncompressed; 0x0304/0x0305 chunks decompressed on the fly).
    Bounds-checks every record (T-04-RESP).
    """
    pairs: list[tuple[str, bytes]] = []
    pos = 0
    n = len(data)
    current_name: str | None = None
    in_table: bool = False
    table_rows: bytearray = bytearray()

    while pos + 4 <= n:
        tag = struct.unpack_from(">H", data, pos)[0]
        length = struct.unpack_from(">H", data, pos + 2)[0]
        pos += 4
        if tag == _TAG_TERMINATOR:
            break
        if length == 0xFFFF:
            if pos + 4 > n:
                raise ValueError(f"malformed TLV: tag 0x{tag:04x} extended form truncated")
            ext_len = struct.unpack_from(">I", data, pos)[0]
            pos += 4
            end = pos + ext_len
            if end > n:
                raise ValueError(
                    f"malformed TLV: tag 0x{tag:04x} extended length {ext_len} "
                    f"exceeds remaining payload ({n - pos} bytes)"
                )
            value = data[pos:end]
            pos = end
        else:
            end = pos + length
            if end > n:
                raise ValueError(
                    f"malformed TLV: tag 0x{tag:04x} length {length} "
                    f"exceeds remaining payload ({n - pos} bytes)"
                )
            value = data[pos:end]
            pos = end
        # Skip close tag
        if pos + 2 <= n and struct.unpack_from(">H", data, pos)[0] == tag:
            pos += 2

        # --- Scalar param tags ---
        if tag == _TAG_PARAM_NAME:  # 0x0201
            # Finalize any in-progress table that was missing its 0x0306 end tag
            if in_table and current_name is not None:
                pairs.append((current_name, bytes(table_rows)))
                in_table = False
                table_rows = bytearray()
            current_name = _decode_utf16le(value)
        elif tag == _TAG_PARAM_VALUE and current_name is not None and not in_table:  # 0x0203
            pairs.append((current_name, value))
            current_name = None

        # --- Table name+begin tag ---
        # BN-CONFIRMED (RfcParameter::rfcSerialize 0x4afdfe): 0x0301 carries the
        # param name UTF-16LE as its value (new format — server uses writeRfcString
        # at 0x4afeab).  Also accept legacy format where a preceding 0x0201 set the
        # name and 0x0301 is empty (begin marker only) — tolerates older captures.
        elif tag == _TAG_TABLE_NAME:  # 0x0301
            if in_table and current_name is not None:
                pairs.append((current_name, bytes(table_rows)))
            if value:  # new format: name in 0x0301 value
                current_name = _decode_utf16le(value)
            # else: legacy format — name already set by preceding 0x0201; keep it
            in_table = True
            table_rows = bytearray()

        # --- Table data tags ---
        elif tag == _TAG_TABLE_INFO and in_table:  # 0x0302
            pass  # row_size / row_count already available from row data length
        elif tag in (_TAG_TABLE_CONTENT, _TAG_TABLE_CONTENT_ALT) and in_table:  # 0x0303/0x0304
            # BN-CONFIRMED: both tags carry raw uncompressed row bytes (rfcDeserialize path)
            table_rows.extend(value)
        elif tag == _TAG_TABLE_CONTENT_LZ and in_table:  # 0x0305
            if len(value) >= 8:
                uncomp_len = struct.unpack_from("<I", value, 0)[0]
                try:
                    table_rows.extend(sapcompress_decompress(value, uncomp_len))
                except DecompressError as exc:
                    raise ValueError(
                        f"SAPCOMPRESS decompression failed for TABLE param "
                        f"{current_name!r} tag 0x{tag:04x}: {exc}"
                    ) from exc
        elif tag == _TAG_TABLE_END and in_table and current_name is not None:  # 0x0306
            pairs.append((current_name, bytes(table_rows)))
            current_name = None
            in_table = False
            table_rows = bytearray()

    # Finalize any unterminated table at end of stream
    if in_table and current_name is not None:
        pairs.append((current_name, bytes(table_rows)))

    return pairs


def _decode_utf16le(value: bytes | None) -> str:
    """Decode UTF-16LE bytes to str, stripping trailing NUL/space padding."""
    if not value:
        return ""
    if len(value) % 2 == 0:
        try:
            return value.decode("utf-16-le").rstrip("\x00 ")
        except Exception:
            pass
    return value.decode("ascii", errors="replace").rstrip("\x00 ")
