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
#       close tag (the TLV closing writer pattern). This is different from session._tlv
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

import logging
import re
import struct
from collections.abc import Iterator
from typing import Any

from saprfclib.codec import decode, encode
from saprfclib.compress import DecompressError, sapcompress_decompress
from saprfclib.exceptions import (
    AbapApplicationError,
    AbapSystemFailure,
    CommunicationError,
    IncompleteDescriptorError,
)
from saprfclib.types import (
    RFC_CHANGING,
    RFC_EXPORT,
    RFC_IMPORT,
    RFC_TABLES,
    FieldDesc,
    FunctionDesc,
)

# rfctype constant for TABLE (RFCTYPE_TABLE = 5 from SDK type definitions / codec.py)
# CONFIRMED: the parameter serializer checks rcx_1 == 5 for TABLE branch
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

# Table protocol tags (CONFIRMED from the parameter serializer +
# the table serializer + the table-info writer)
#
# 0x0301 is the TABLE NAME TAG — it carries the param name UTF-16LE as its value
# and replaces 0x0201 for rfctype==5 params.  There is NO separate empty "begin"
# marker before it.  REQUEST sequence:
#   0x0301(name) → [0x0330(dm_id)] → 0x0302(row_size+row_count) → 0x0303* → 0x0306
# RESPONSE sequence (server uses the same serializer path — symmetric):
#   0x0301(name) → 0x0302(info) → {0x0303|0x0304|0x0305}* → 0x0306
_TAG_TABLE_NAME = 0x0301  # TABLE param name tag (replaces 0x0201 for TABLE rfctype)
_TAG_TABLE_BEGIN = 0x0301  # alias: same tag received in responses (name+begin combined)
_TAG_TABLE_INFO = 0x0302  # 8B: [0-3] BE uint32 row_size, [4-7] BE uint32 row_count
_TAG_TABLE_CONTENT = 0x0303  # uncompressed row data (RFCID_TableContent)
# CONFIRMED (the bounded reader case 3): 0x0304 (RFCID_TableCompr) is
# also raw row data — the same deserializer path as 0x0303 despite the misleading name.
_TAG_TABLE_CONTENT_ALT = 0x0304  # raw row data, alternate tag (RFCID_TableCompr)
_TAG_TABLE_CONTENT_LZ = (
    0x0305  # SAPCOMPRESS compressed rows (RFCID_TableContLZ; rfcDeserializeCompressed)
)
_TAG_TABLE_END = 0x0306  # table-stream end marker. Accepted when reading; never
# written on a request — see build_invoke_request. No capture in this repo shows it
# in either direction, so the read-side handling is defensive, not evidence-backed.
# Server-returned form of a table the CLIENT supplied as input. The table is
# identified by the DM table ID the client assigned it in 0x0330 — NOT by name.
#
# 0x0335 value is 12 bytes: three BE uint32 [opcode=10, dm_table_id, row_count],
# followed by the usual 0x0302 info record and 0x0304 row records, terminated by
# 0x0336 (4 bytes).  Confirmed live (kernel 793) by varying the row count while
# holding the DM id fixed:
#   FIELDS sent with dm_id=1, 2 rows -> 0x0335 = [10, 1, 2]
#   FIELDS sent with dm_id=1, 4 rows -> 0x0335 = [10, 1, 4]
# In the same responses DATA and OPTIONS — tables the client did NOT send — come
# back under 0x0301 carrying their names, with server-assigned 0x0330 ids.
_TAG_TABLE_DELTA = 0x0335
_TAG_TABLE_DELTA_END = 0x0336
_DELTA_OPCODE = 10  # first uint32 of the 0x0335 header; only value observed
_logger = logging.getLogger(__name__)

# XML-encoded table rows (tags 0x3c02 / 0x3c05).
#
# A table sent this way is bracketed by an empty 0x3c02 pair, with plain-text XML
# carried in 0x3c05 chunks as ASCII — NOT the UTF-16LE every other string-bearing tag
# uses. Confirmed live twice:
#   empty:      0x3c02 | 0x3c05 '<ET_DATA>' | 0x3c05 '</ET_DATA>' | 0x3c02
#   populated:  0x3c05 '<ET_DATA>' | 0x3c05 '<item><LINE>a|b|c</LINE></item></ET_DATA>'
# Sources: tests/golden/framing/rfc_read_table_response.bin and
# basxml_et_data_response.bin (the latter contributed via issue #29).
#
# NOT to be confused with SAP's BASXML, which issue #18 tracks and which is NOT
# implemented. That is a binary tokenised format: BasXmlRenderer emits a header
# beginning with the literal magic "BXML", then token bytes and a string table (an
# element open is the byte 0x3c followed by a string-table index, not the text "<"),
# under the http://www.sap.com/abapxml namespace, and BasXMLParser reads it back with
# length-prefixed strings. The two share a TLV tag and nothing else. A payload
# carrying the BXML magic is refused outright rather than fed to the text reader —
# see _BASXML_BINARY_MAGIC.
_TAG_BASXML_MARKER = 0x3C02
_TAG_BASXML_DATA = 0x3C05
_BASXML_OPEN = b"<"
# SAP's binary BASXML document magic. Its presence means the peer negotiated the
# tokenised format that issue #18 covers; the text reader below would produce
# nonsense from it, so it is rejected with a clear message instead.
_BASXML_BINARY_MAGIC = b"BXML"
# Sentinel: inside a BASXML block but the table name has not been read yet. A plain
# string, so `is` comparisons distinguish it from a real table called anything.
_BASXML_PENDING = "\x00pending"

_SAPCOMPRESS_MAGIC = b"\x1f\x9d"  # compress.py header magic, at stream offset 5
_SAPCOMPRESS_HDR = 8  # [4B LE uncompressed length][algo][2B magic][config]
_LZ_WRAPPER = 8  # bytes preceding the SAPCOMPRESS stream in a joined 0x0305 payload
_TAG_DM_TABLE_ID = 0x0330  # 4B BE uint32 DM table tracking ID (getNextDMTableId counter)

# Response-only tags (confirmed from golden response fixture)
_TAG_RESPONSE_START = 0x0500  # empty: response start marker
_TAG_RETURN_CODE = 0x0420  # 4B BE uint32 return code (0=success)

# Exception tags. 0x0417 doubles as the "this is an exception" marker and the ABAP
# message number; 0x0401 carries the exception name.
#
# CONFIRMED by three live exception replies:
#   RFC_READ_TABLE on a table it will not read (kernel 793):
#     0x0415 'DA'  0x0416 'E'  0x0417 '131'  0x0411 'T001'  0x0401 'TABLE_NOT_AVAILABLE'
#   RFC_GET_FUNCTION_INTERFACE for a non-RFC-enabled FM (kernels 793 and 742):
#     0x0415 'FL'  0x0416 'E'  0x0417 '046'  0x0411 '<FM name>'  0x0401 'FU_NOT_FOUND'
#   tests/golden/framing/stfc_exception_response.bin (RAISE with no MESSAGE):
#     0x0417 '000'  0x0401 'EXAMPLE'   — the message fields are simply absent
#
# In each, 0x0415 is the two-character message class, 0x0416 the single-character
# type, 0x0417 the three-digit number and 0x0411 the first message variable. The
# previous 0x0402-0x0408 mapping came from documentation rather than a capture and
# does not match any of them — 0x0402 is the logon/system error message text
# (_TAG_ERROR_MESSAGE), not the message class.
_TAG_EXCEPTION_NUMBER = 0x0417  # ABAP message number, e.g. "046"
_TAG_EXCEPTION_KEY = 0x0401  # exception name, e.g. "FU_NOT_FOUND"
_TAG_EXCEPTION_MSG_CLASS = 0x0415  # message class, e.g. "FL"
_TAG_EXCEPTION_MSG_TYPE = 0x0416  # message type, e.g. "E"
_TAG_EXCEPTION_MSG_NUMBER = 0x0417  # same tag as the marker above
_TAG_EXCEPTION_MSG_V1 = 0x0411  # first message variable
# [ASSUMED] V2-V4 follow V1 consecutively. No capture yet carries more than one
# variable, so these are inference from 0x0411; a reply that fills them would confirm
# or correct them. They are read defensively — an absent tag simply yields None.
_TAG_EXCEPTION_MSG_V2 = 0x0412
_TAG_EXCEPTION_MSG_V3 = 0x0413
_TAG_EXCEPTION_MSG_V4 = 0x0414
_TAG_EXCEPTION_MESSAGE = 0x040B  # [ASSUMED] free-text message; not seen in any capture

# RFC version string (confirmed from golden fixture)
_RFC_VERSION = b"754"


# --------------------------------------------------------------------------- #
# Full-record TLV builder (open + close markers)
# --------------------------------------------------------------------------- #


def tlv_record(tag: int, data: bytes = b"") -> bytes:
    """Build one full-record TLV: [tag BE][len BE][data][tag BE].

    Uses the extended form (tag + 0xFFFF + ext-len 4B BE + data + tag) when
    len >= 0xFFFF (65535 bytes), per framing.md §"TLV Record Format"
    (the TLV opening writer / the TLV closing writer).

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


def unknown_parameters(desc: FunctionDesc, params: dict[str, Any]) -> list[str]:
    """Return the caller-supplied names the function interface does not declare.

    Names are matched case-insensitively, as ``build_invoke_request`` matches them.
    Returned in sorted order so messages are stable.
    """
    known = {f.name.upper() for f in desc.parameters}
    return sorted(name for name in params if name.upper() not in known)


def drop_unknown_parameters(desc: FunctionDesc, params: dict[str, Any]) -> dict[str, Any]:
    """Return ``params`` without the names the function interface does not declare."""
    known = {f.name.upper() for f in desc.parameters}
    return {name: value for name, value in params.items() if name.upper() in known}


def dm_table_ids(desc: FunctionDesc, params: dict[str, Any]) -> dict[int, str]:
    """Return ``{dm_table_id: param_name}`` for the tables this call sends with rows.

    The client assigns each outgoing TABLE parameter a DM table ID (tag 0x0330),
    numbered from 1 in parameter order, counting only tables that actually carry
    rows.  The server uses that ID — not the parameter name — to identify the table
    when it sends the data back (tag 0x0335), so the caller must keep the mapping to
    make sense of the response.

    Shares its assignment rule with ``build_invoke_request`` by construction: the
    builder calls this function rather than counting separately.
    """
    params_upper = {k.upper(): v for k, v in params.items()}
    assigned: dict[int, str] = {}
    next_id = 0
    for field in desc.parameters:
        if field.direction == RFC_EXPORT:
            continue
        value = params_upper.get(field.name.upper())
        if field.rfctype != _RFCTYPE_TABLE or not value:
            continue
        next_id += 1
        assigned[next_id] = field.name
    return assigned


def build_invoke_request(
    func_name: str,
    desc: FunctionDesc,
    params: dict[str, Any],
    *,
    version: bytes = _RFC_VERSION,
) -> bytes:
    """Build the RFC invoke TLV payload (from offset 80 onward, NOT the GW header).

    TLV order (framing.md §"RFC Function Call Sequence", confirmed from golden fixture +
    protocol analysis of RfcFunction::rfcSerializeParams):
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

    Direction routing (Pitfall 3: caller perspective, CONFIRMED):
      RFC_EXPORT (0x02): ABAP EXPORTING → server sends back → 0x0205 decl only
      RFC_IMPORT (0x01): ABAP IMPORTING → caller sends → 0x0201+0x0203 (scalar/struct)
      RFC_CHANGING (0x03): caller sends AND receives → 0x0205 decl + 0x0201+0x0203 value
      RFC_TABLES (0x07): tables → 0x0205 decl + 0x0301+table protocol if rows supplied

    TABLE protocol (CONFIRMED from the parameter serializer +
    the table serializer + the table-info writer):
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
    # rfcSupplyOutParam at — direction bit 1 set (0x02, 0x03, 0x07) triggers this.
    for field in desc.parameters:
        if field.direction in (RFC_EXPORT, RFC_CHANGING, RFC_TABLES):
            parts.append(tlv_record(_TAG_EXPORT_DECL, field.name.encode("utf-16-le")))

    # Emit param values for caller-supplied IMPORTING/CHANGING/TABLES params.
    params_upper = {k.upper(): v for k, v in params.items()}

    # A parameter the descriptor does not know cannot be encoded, and the loop below
    # would simply never reach it — the value would be dropped from the request with
    # no diagnostic, and the server would run the function without it. Fail loudly
    # instead: silently omitting an argument the caller passed is the worst outcome.
    unknown = unknown_parameters(desc, params)
    if unknown:
        raise ValueError(
            f"{func_name}: parameter(s) {', '.join(unknown)} are not in the function "
            f"interface; known parameters are "
            f"{', '.join(sorted(f.name for f in desc.parameters)) or '(none)'}"
        )
    # DM table IDs assigned by the shared helper so the response parser can map
    # tag 0x0335 back to a parameter name (see dm_table_ids).
    _dm_ids = {name: dm for dm, name in dm_table_ids(desc, params).items()}
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
            if field.type_desc is None:
                # Not an assert: assertions vanish under `python -O`, and this one
                # guards a real runtime condition — the RFC_GET_STRUCTURE_DEFINITION
                # lookup for the row type failed, so there is no layout to encode to.
                raise IncompleteDescriptorError(
                    f"cannot encode TABLE parameter {field.name!r}: its row layout "
                    f"was never resolved (type_desc is None). The "
                    f"RFC_GET_STRUCTURE_DEFINITION lookup for its DDIC type did not "
                    f"complete."
                )
            all_row_bytes = encode(_RFCTYPE_TABLE, rows, field)
            row_size = field.type_desc.uc_size if field.unicode_mode else field.type_desc.nuc_size
            row_count = len(rows)
            parts.append(tlv_record(_TAG_TABLE_NAME, field.name.encode("utf-16-le")))
            parts.append(tlv_record(_TAG_DM_TABLE_ID, struct.pack(">I", _dm_ids[field.name])))
            parts.append(tlv_record(_TAG_TABLE_INFO, struct.pack(">II", row_size, row_count)))
            for i in range(row_count):
                row_slice = all_row_bytes[i * row_size : (i + 1) * row_size]
                parts.append(tlv_record(_TAG_TABLE_CONTENT, row_slice))
            # NO end tag. A client-written table is terminated by the next record,
            # not by 0x0306 — the SDK's table serializer emits name, DM id, info and
            # rows and nothing else, and neither golden capture contains 0x0306 in a
            # request. Emitting one makes the server tear down the gateway
            # conversation: the call returns an 80-byte header-only frame and every
            # subsequent call on that connection fails with
            # "Conversation NNN not found" (verified live on kernel 793 — removing
            # the tag is the single change that turns the failure into a success).
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
# CONFIRMED (Plan 06-01): tRFC and qRFC are ordinary synchronous RFC calls
# to the SAP system function module ARFC_DEST_SHIP.  There are NO new TLV tags
# for the call-type discriminator — the function name in TLV 0x0102 IS the
# discriminator (RfcServer::dispatch).  The TID is carried as a CHAR
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

_TID_LN = 24  # RFC_TID_LN from SDK type definitions
_MAX_QUEUE_NAME = 256  # conservative upper bound (SDK type definitions §RFC_MAX_QUEUE_NAME_LENGTH)

# TID character alphabet confirmed by protocol analysis.
_TID_ALPHABET: frozenset[str] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-")

# System FM names (protocol analysis).
_ARFC_DEST_SHIP = "ARFC_DEST_SHIP"
_ARFC_DEST_CONFIRM = "ARFC_DEST_CONFIRM"


def _validate_tid(tid: str) -> None:
    """Raise ValueError if tid is not a valid 24-char TID (T-06-C02 / V5).

    TID must be exactly RFC_TID_LN (24) characters from the confirmed alphabet
    ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-.  A UUID-hex TID (uppercase, digits
    only) is a valid subset and accepted.

    Source: SDK type definitions (RFC_TID_LN=24) (alphabet).
    """
    if not isinstance(tid, str):
        raise ValueError(f"TID must be a str, got {type(tid).__name__!r}")
    if len(tid) != _TID_LN:
        raise ValueError(f"TID must be exactly {_TID_LN} characters (RFC_TID_LN); got {len(tid)}")
    bad = [c for c in tid if c not in _TID_ALPHABET]
    if bad:
        raise ValueError(
            f"TID contains characters not in the RFC alphabet: {bad!r} "
            f"(allowed: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-)"
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
    0x0102 (the call-type discriminator per).  The TID and the
    wrapped function name are encoded as named CHAR parameters (UTF-16LE).

    For qRFC (queue is not None): the queue name is included as an additional
    CHAR parameter (ARFCQUEUE) so the server can read the queue indicator at
    ARFCSSTATE offset 0xe58.

    Security: validates TID length and alphabet, queue name length before encoding
    (T-06-C02 / RESEARCH V5).

    OG-06-01 CONFIRMED (2026-08-05): named-param encoding confirmed via live qRFC gate.
    TID as ARFCTID param works; no raw ARFCSSTATE field decomposition needed.

    Args:
        tid:       24-char TID from the RFC TID alphabet.
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
    for this TID (SDK type definitions — never call before verifying the submit landed).

    Security: validates TID before encoding (T-06-C02).

    Confirmed: the ARFC_DEST_CONFIRM branch of the server dispatch.
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
# CONFIRMED (Plan 06-01): bgRFC uses BGRFC_DEST_SHIP / BGRFC_DEST_CONFIRM /
# BGRFC_CHECK_UNIT_STATE_SERVER function-module names (RfcServer::dispatch).
# The UnitID is a 32-char uppercase hex string (: the UUID formatter asserts
# len == 32).  Unit type is 'T' (no queues) or 'Q' (queues given).
#
# OG-06-02 CONFIRMED (2026-08-05): test_live_bgrfc_unit_lifecycle passed — BGRFC_UNIT_ID/
# BGRFC_UNIT_TYPE named-param encoding confirmed correct by live bgRFC gate.  No raw
# BGRFC_SRV_STATE/ARFCSDATA struct layout needed — server reads only the named params.
# Source: discriminator + live bgRFC gate.
#
# Security (T-06-U02): UnitID length is enforced to exactly RFC_UNITID_LN=32 hex chars
# before encoding. queue_names are bounded.

_UNITID_LN = 32  # RFC_UNITID_LN from SDK type definitions
_UNITID_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# System FM names (protocol analysis).
_BGRFC_DEST_SHIP = "BGRFC_DEST_SHIP"
_BGRFC_DEST_CONFIRM = "BGRFC_DEST_CONFIRM"
_BGRFC_CHECK_UNIT_STATE_SERVER = "BGRFC_CHECK_UNIT_STATE_SERVER"

# Unit type bytes: 'T' (0x54) = no queues; 'Q' (0x51) = queues given.
_UNIT_TYPE_T = "T"
_UNIT_TYPE_Q = "Q"


def _validate_unit_id(uid: str) -> None:
    """Raise ValueError if uid is not a valid 32-char uppercase hex UnitID (T-06-U02 / V5).

    UnitID must be exactly RFC_UNITID_LN (32) characters of uppercase hex (0-9A-F).
    Source: SDK type definitions (RFC_UNITID_LN=32) (the UUID formatter → 32 hex chars).
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
            f"UnitID contains characters not in uppercase hex alphabet: {bad!r} (allowed: 0-9A-F)"
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
    0x0102 (the call-type discriminator per). The UnitID and
    unit_type are encoded as named CHAR parameters (UTF-16LE).

    Open gap OG-06-02: the exact BGRFC_DEST_SHIP parameter byte layout is deferred
    to the D-08 live-capture gate. UnitID and unit_type are encoded as standalone
    CHAR params (BGRFC_UNIT_ID, BGRFC_UNIT_TYPE) until the exact structure is known.

    Security: validates UnitID length and hex charset before encoding (T-06-U02 / V5).

    Args:
        unit_id:        32-char uppercase hex UnitID.
        unit_type:      'T' (no queues) or 'Q' (queues given).
        queue_names:    List of queue names (empty for type 'T').
        buffered_calls: Optional list of pre-serialized call TLV bytes to embed.
        version:        RFC version string bytes (default b"754").

    Returns:
        Raw TLV payload bytes (not the full GW frame).
    """
    _validate_unit_id(unit_id)
    if unit_type not in (_UNIT_TYPE_T, _UNIT_TYPE_Q):
        raise ValueError(f"unit_type must be 'T' or 'Q', got {unit_type!r}")

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
        # Unit type — 'T' or 'Q'
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

    Confirmed: the BGRFC_DEST_CONFIRM branch of the server dispatch.
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

    Confirmed: the BGRFC_CHECK_UNIT_STATE_SERVER branch of the server dispatch.
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


_GATEWAY_ERROR_MARKER = b"*ERR*"
_GATEWAY_ERROR_MESSAGE_FIELD = 2  # NUL-separated: marker, code, message, ...


def parse_gateway_error(payload: bytes) -> str | None:
    """Return the human-readable text of a SAP gateway error frame, if this is one.

    The gateway answers a frame it will not process with a NUL-separated record
    rather than TLV, bracketed by ``*ERR*``::

        *ERR*\x001\x00Conversation 50633926 not found\x00728\x00SAP-Gateway
        \x00793\x002\x00/bas/793_REL/src/krn/si/gw/gwxxconn.c\x00960\x00...

    Field 2 carries the message; the rest are an error number, the reporting
    component, the kernel release and the source location that raised it.

    Recognising this matters because the bytes are not TLV at all. Walking them as
    TLV reads ``*E`` as a tag and ``RR`` as a length, which surfaced to a reporter as
    "malformed TLV: tag 0x2a45 length 21074" — an error that says nothing about the
    conversation having been torn down.
    """
    if not payload.startswith(_GATEWAY_ERROR_MARKER):
        return None
    fields = payload.split(b"\x00")
    parts: list[str] = []
    for idx in (_GATEWAY_ERROR_MESSAGE_FIELD, 4, 5):
        if idx < len(fields):
            text = fields[idx].decode("utf-8", "replace").strip()
            if text:
                parts.append(text)
    return " | ".join(parts) if parts else payload.decode("utf-8", "replace")[:200]


_CPIC_PRINTABLE_RATIO = 0.7  # below this, the EBCDIC reading is not text


def parse_cpic_error(payload: bytes) -> str | None:
    """Return the text of a CPIC-layer error frame, if this payload is one.

    When the conversation fails below the RFC layer the peer answers in EBCDIC
    rather than TLV. Observed live (kernel 793) for every call attempted without a
    completed logon — no logon frame at all, credentials omitted, and credentials
    empty all produced the identical 97-byte body::

        c6 d9 c5 c5 40 40 40 40  f1 40 00 00  f0 f0 f0 f2 f4  85 99 99 96 99 ...
        F  R  E  E  (spaces)     1     ...    0  0  0  2  4   e  r  r  o  r  ...

    decoding to ``FREE 1 00024error during logon``.

    Deliberately not parsed into fields. One capture is not enough to claim the
    layout — what "FREE" and the numbers mean is unconfirmed — but the message text
    is plainly useful, and surfacing it beats reporting an unreadable response.
    Distinct from ``_COM_HEAD``, the EBCDIC "RFC000000000" that prefixes a logon
    frame in the other direction.

    Returns None for anything that does not read as EBCDIC text, so a genuine TLV
    frame is never mistaken for one; verified against every golden response fixture.
    """
    if not payload:
        return None
    raw = payload.rstrip(b"\x00\x20\x40")  # NUL, ASCII space, EBCDIC space
    if not raw:
        return None
    try:
        text = raw.decode("cp500")
    except (UnicodeDecodeError, LookupError):
        return None
    printable = sum(1 for ch in text if ch.isprintable())
    if printable / len(text) < _CPIC_PRINTABLE_RATIO:
        return None
    words = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    if not words or not re.search(r"[A-Za-z]{4,}", words):
        return None
    return words


def raise_for_rfc_error(resp: bytes, *, _tags: dict[int, bytes] | None = None) -> None:
    """Raise the typed error an RFC response carries, if it carries one.

    Shared by every reader of a response, so a failure is classified the same way
    wherever it arrives. Metadata bootstraps used to skip this entirely: a function
    module that is not remote-enabled answers RFC_GET_FUNCTION_INTERFACE with a
    normal ABAP exception (message class FL, number 046, name FU_NOT_FOUND), and
    because an exception reply carries no 0x0420 the return-code check never fired.
    The result was an empty descriptor and no diagnostic, so the next call rejected
    every argument the caller passed as "unknown".

    Deliberately not special-cased to FU_NOT_FOUND — any exception the server reports
    during metadata retrieval is surfaced with its full message detail.

    Raises:
        AbapApplicationError: the response carries ABAP exception tags.
        AbapSystemFailure: the return code is non-zero.
    """
    gateway_error = parse_gateway_error(resp)
    if gateway_error is not None:
        raise CommunicationError(
            f"the SAP gateway rejected the frame: {gateway_error}. The conversation "
            f"is gone; this connection should be discarded rather than retried."
        )

    if _tags is None:
        try:
            tags = _parse_tlv_stream(resp)
        except ValueError as exc:
            # Not an RFC response at all. Before reporting the tag and length read
            # out of whatever the bytes actually were, see whether the peer answered
            # below the RFC layer — a CPIC error frame is EBCDIC, not TLV.
            cpic = parse_cpic_error(resp)
            if cpic is not None:
                raise CommunicationError(
                    f"the connection failed below the RFC layer: {cpic}"
                ) from exc
            preview = resp[:40].decode("utf-8", "replace")
            raise CommunicationError(
                f"the response is not a readable RFC message ({len(resp)} bytes, "
                f"starting {preview!r}): {exc}"
            ) from exc
    else:
        tags = _tags

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

    rc_bytes = tags.get(_TAG_RETURN_CODE)
    if rc_bytes is not None:
        if len(rc_bytes) != 4:
            raise ValueError(f"return-code TLV 0x0420 has length {len(rc_bytes)}, expected 4")
        rc = struct.unpack(">I", rc_bytes)[0]
        if rc != 0:
            raise AbapSystemFailure(
                msg_class=_decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_CLASS)) or None,
                msg_type=_decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_TYPE)) or None,
                msg_number=_decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_NUMBER)) or None,
                msg_v1=_decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V1)) or None,
                msg_v2=_decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V2)) or None,
                msg_v3=_decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V3)) or None,
                msg_v4=_decode_utf16le(tags.get(_TAG_EXCEPTION_MSG_V4)) or None,
                message=_decode_utf16le(tags.get(_TAG_EXCEPTION_MESSAGE))
                or f"RFC return code {rc}",
            )


def parse_invoke_response(
    resp: bytes, desc: FunctionDesc, dm_table_names: dict[int, str] | None = None
) -> dict[str, Any]:
    """Parse a RFC invoke response TLV stream and return a native-typed dict.

    Walks the TLV stream with bounds-checking (T-04-RESP, mirrors session._parse_tlv).
    Classification logic (confirmed from stfc_exception_response.bin golden fixture):
      - Tag 0x0417 present → AbapApplicationError (ABAP exception)
      - Tag 0x0420 non-zero and no exception tags → AbapSystemFailure
      - Tag 0x0420 == 0 → success; walk 0x0201/0x0203 pairs and decode values

    Pitfall 4: 0x0420 return code is 4B BE uint32 (use struct.unpack('>I')).
    Pitfall 2: value bytes from 0x0203 are passed directly to codec.decode — let
    the codec handle type-specific length/encoding (UTF-16 code-unit math, BCD, etc.).

    ``dm_table_names`` maps DM table IDs to parameter names for tables the caller
    sent as input; the server returns those under tag 0x0335 keyed by ID rather than
    by name. Pass ``dm_table_ids(desc, params)`` for the same call, or such
    parameters are absent from the result.
    """
    tags = _parse_tlv_stream(resp)
    raise_for_rfc_error(resp, _tags=tags)

    # Every genuine invoke response carries the return code; only an exception
    # response omits it, and that is raised above. Its absence means the call did not
    # complete — most commonly the gateway aborted the conversation and replied with a
    # bare header (observed live: an 80-byte frame with no TLV body at all, after
    # which every further call on the connection fails with "Conversation NNN not
    # found"). Reporting that as an empty successful result hides a dead connection
    # and surfaces later as a confusing KeyError in caller code.
    rc_bytes = tags.get(_TAG_RETURN_CODE)
    if rc_bytes is None:
        raise CommunicationError(
            f"malformed RFC response: no return-code TLV 0x{_TAG_RETURN_CODE:04x} and no "
            f"exception tags in {len(resp)} byte(s) of response payload — the server "
            f"aborted the call; this connection should be discarded"
        )
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
    basxml: dict[str, bytes] = {}
    # Walk the ordered tag list to pick up 0x0201+0x0203 pairs
    for name, value in _extract_name_value_pairs(resp, dm_table_names, basxml):
        name_upper = name.upper()
        match_field: FieldDesc | None = param_map.get(name_upper)
        if match_field is None:
            continue  # unknown param name — ignore (defensive)
        result[match_field.name] = decode(match_field.rfctype, value, match_field)

    # BASXML-encoded tables carry XML text rather than a flat row buffer, so they
    # bypass the codec entirely (see decode_basxml_table).
    for name, payload in basxml.items():
        match_field = param_map.get(name.upper())
        if match_field is None:
            continue
        result[match_field.name] = decode_basxml_table(payload, match_field.name)

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


_BASXML_MAX_BYTES = 64 * 1024 * 1024  # refuse absurd payloads (T-04-RESP)
_BASXML_MAX_ITEMS = 1_000_000
_BASXML_ENTITIES = {
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "quot": '"',
    "apos": "'",
}


def _xml_unescape(text: str) -> str:
    """Resolve the five predefined XML entities plus numeric character references.

    Deliberately hand-rolled rather than using an XML library: this payload arrives
    from the peer (trust boundary T-04-RESP), and the stdlib parsers accept DTDs and
    entity definitions, which brings entity-expansion exposure for no benefit here.
    The BASXML grammar in play is elements with text content and nothing else — no
    attributes, no namespaces, no processing instructions — so a bounded scanner
    covers it exactly and offers no such surface.
    """
    if "&" not in text:
        return text
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "&":
            out.append(ch)
            i += 1
            continue
        end = text.find(";", i + 1, i + 12)
        if end == -1:
            out.append(ch)
            i += 1
            continue
        ref = text[i + 1 : end]
        if ref.startswith("#"):
            try:
                code = int(ref[2:], 16) if ref[1:2].lower() == "x" else int(ref[1:])
                out.append(chr(code))
                i = end + 1
                continue
            except (ValueError, OverflowError):
                pass
        elif ref in _BASXML_ENTITIES:
            out.append(_BASXML_ENTITIES[ref])
            i = end + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _basxml_elements(text: str, start: int, end: int) -> Iterator[tuple[str, int, int]]:
    """Yield (tag, inner_start, inner_end) for direct child elements between start/end."""
    pos = start
    while pos < end:
        open_lt = text.find("<", pos, end)
        if open_lt == -1:
            return
        open_gt = text.find(">", open_lt + 1, end)
        if open_gt == -1:
            return
        tag = text[open_lt + 1 : open_gt]
        if tag.startswith("/") or tag.startswith("?") or tag.startswith("!"):
            pos = open_gt + 1
            continue
        if tag.endswith("/"):  # self-closing: empty value
            yield tag[:-1].strip(), open_gt + 1, open_gt + 1
            pos = open_gt + 1
            continue
        closing = f"</{tag}>"
        close_at = text.find(closing, open_gt + 1, end)
        if close_at == -1:
            return
        yield tag, open_gt + 1, close_at
        pos = close_at + len(closing)


def decode_basxml_table(payload: bytes, table_name: str = "") -> list[dict[str, str]]:
    """Decode a BASXML table body into row dicts.

    Wire form, confirmed live (kernel 793, RFC_READ_TABLE with
    USE_ET_DATA_4_RETURN='X', contributed via issue #29)::

        <ET_DATA><item><LINE>VAL1|VAL2|VAL3</LINE></item></ET_DATA>

    The payload is ASCII, not the UTF-16LE every other string-bearing tag uses, and
    arrives split across 0x3c05 records that must be joined before parsing.

    Each ``<item>`` becomes one row and each element inside it a key. The observed
    form carries the whole delimited row in a single ``<LINE>`` element, but the
    documented form puts one element per field, so both are handled by the same walk:
    whatever elements an item contains become that row's keys.

    Multi-row is confirmed, not inferred: a ten-row T100 read arrived as ten
    ``<item>`` elements split across two 0x3c05 fragments of 9 and 773 bytes — the
    first holding only the opening tag. Fragment boundaries fall wherever the server
    chooses and not on item boundaries, which is why the fragments are joined before
    parsing rather than parsed one at a time.

    One difference from the binary encoding worth knowing: the XML form does NOT
    blank-pad fields to their DDIC width. The same query returns ``ARBGB`` as
    ``'FL'`` here and as ``'FL'`` plus eighteen spaces through ``DATA``. Row content
    is otherwise identical field for field.

    Values are returned as text. No type conversion is applied, because the element
    carries no type information and the row is delimited exactly as the caller's
    DELIMITER specified; splitting or converting it is the caller's decision, as it
    is for ``DATA``.
    """
    if payload[:4] == _BASXML_BINARY_MAGIC:
        raise NotImplementedError(
            f"table {table_name!r} arrived in SAP's binary BASXML encoding (BXML "
            f"magic), which is not implemented — see "
            f"https://github.com/randomstr1ng/saprfclib/issues/18. This is a "
            f"different format from the plain-text XML tables saprfclib does decode; "
            f"decoding it as text would produce nonsense."
        )
    if len(payload) > _BASXML_MAX_BYTES:
        raise ValueError(
            f"BASXML payload for table {table_name!r} is {len(payload)} bytes, "
            f"over the {_BASXML_MAX_BYTES} byte cap"
        )
    text = payload.decode("utf-8", errors="replace")

    # Skip any XML declaration, DTD or comment before the root element. No server has
    # been observed sending one, but skipping them keeps the structure walk
    # predictable on unexpected input instead of treating the prologue as data.
    scan = 0
    while scan < len(text):
        nxt = text.find("<", scan)
        if nxt == -1 or text[nxt + 1 : nxt + 2] not in ("?", "!"):
            break
        depth, i = 0, nxt
        while i < len(text):
            if text[i] == "<":
                depth += 1
            elif text[i] == ">":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        scan = i + 1
    text = text[scan:] if scan else text

    # Enter the outer <TABLE> wrapper if present; tolerate its absence.
    body_start, body_end = 0, len(text)
    first_gt = text.find(">")
    if text[:1] == "<" and first_gt != -1:
        wrapper = text[1:first_gt]
        closing = f"</{wrapper}>"
        close_at = text.rfind(closing)
        if close_at != -1:
            body_start, body_end = first_gt + 1, close_at

    rows: list[dict[str, str]] = []
    for tag, inner_start, inner_end in _basxml_elements(text, body_start, body_end):
        if len(rows) >= _BASXML_MAX_ITEMS:
            raise ValueError(f"BASXML table {table_name!r} exceeds the {_BASXML_MAX_ITEMS} row cap")
        row: dict[str, str] = {}
        for name, vs, ve in _basxml_elements(text, inner_start, inner_end):
            row[name] = _xml_unescape(text[vs:ve])
        if not row:
            # An item with no child elements: keep its text under the item tag so
            # the row is not silently lost.
            row = {tag: _xml_unescape(text[inner_start:inner_end])}
        rows.append(row)
    return rows


def decompress_table_stream(chunks: list[bytes], param_name: str = "") -> bytes:
    """Decompress the SAPCOMPRESS stream carried by a table's 0x0305 records.

    The records are FRAGMENTS OF ONE STREAM, not independently compressed blocks:
    they must be concatenated before anything can be decompressed. The joined
    payload then begins with an 8-byte wrapper — [4B unidentified][4B BE length of
    the compressed stream] — followed by the SAPCOMPRESS stream itself, whose own
    8-byte header is [4B LE uncompressed length][algo byte][2B magic 1f 9d][config].

    Confirmed live (kernel 793) from the RFC_GET_FUNCTION_INTERFACE response for
    BAPI_USER_GET_DETAIL: eight 0x0305 records of 250 bytes join into 2000 bytes;
    the wrapper reports a 1921-byte compressed stream starting at offset 8; the
    SAPCOMPRESS header there declares 17776 uncompressed bytes, matching the 0x0302
    record exactly (row_size 404 x row_count 44), and LZH decompression yields
    precisely that.

    The wrapper is located by the magic rather than assumed, so a stream that
    arrives without one still decodes.
    """
    blob = b"".join(chunks)
    if len(blob) < _SAPCOMPRESS_HDR:
        raise ValueError(
            f"SAPCOMPRESS payload for TABLE param {param_name!r} is too short: {len(blob)} byte(s)"
        )
    if blob[_LZ_WRAPPER + 5 : _LZ_WRAPPER + 7] == _SAPCOMPRESS_MAGIC:
        stream = blob[_LZ_WRAPPER:]
    elif blob[5:7] == _SAPCOMPRESS_MAGIC:
        stream = blob
    else:
        raise ValueError(
            f"SAPCOMPRESS header not found for TABLE param {param_name!r}: "
            f"no 1f9d magic at offset 5 or {_LZ_WRAPPER + 5}"
        )
    uncomp_len = struct.unpack_from("<I", stream, 0)[0]
    try:
        return sapcompress_decompress(stream, uncomp_len)
    except DecompressError as exc:
        raise ValueError(
            f"SAPCOMPRESS decompression failed for TABLE param {param_name!r}: {exc}"
        ) from exc


def _basxml_open_tag(chunk: bytes) -> str | None:
    """Return the table name if this chunk opens a BASXML document, else None."""
    if not chunk.startswith(_BASXML_OPEN):
        return None
    text = chunk.decode("ascii", "replace")
    close = text.find(">")
    if close == -1:
        return None
    name = text[1:close]
    return None if name.startswith("/") or not name else name


def _extract_name_value_pairs(
    data: bytes,
    dm_table_names: dict[int, str] | None = None,
    basxml_out: dict[str, bytes] | None = None,
) -> list[tuple[str, bytes]]:
    """Walk TLV stream and return ordered (name_str, value_bytes) pairs.

    Handles both scalar params and TABLE params:

    Scalar: 0x0201(name) → 0x0203(value)

    TABLE (CONFIRMED from the parameter serializer):
      0x0301(name)  ← combined name+begin; value is param name UTF-16LE
      0x0302(info)  ← 8B [BE row_size][BE row_count] (informational; ignored here)
      {0x0303|0x0304|0x0305}* rows  ← uncompressed or SAPCOMPRESS compressed
      0x0306(end)   ← yields (name, concatenated_row_bytes) pair

    A table the CLIENT supplied as input comes back under a second tag pair,
    0x0335 … 0x0336, and is identified by the DM table ID the client assigned it in
    0x0330 rather than by name — the 0x0335 value is three BE uint32
    [opcode=10, dm_table_id, row_count].  ``dm_table_names`` maps those IDs back to
    parameter names; build it with ``dm_table_ids(desc, params)`` for the same call.
    Without it such tables cannot be identified and their rows are skipped.

    Observed live (kernel 793): RFC_READ_TABLE called with FIELDS populated returns
    DATA and OPTIONS under 0x0301 with their names, and FIELDS — the table we sent —
    under 0x0335 with dm_table_id 1.

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
    table_lz: list[bytes] = []  # 0x0305 fragments of one compressed stream
    basxml_chunks: dict[str, list[bytes]] = {}  # table name -> 0x3c05 fragments
    basxml_current: str | None = None  # None outside a block, _BASXML_PENDING inside
    # one whose name is not yet known

    def _payload() -> bytes:
        """Row bytes for the table just finished, decompressing 0x0305 if used."""
        if table_lz:
            return decompress_table_stream(table_lz, current_name or "")
        return bytes(table_rows)

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
                pairs.append((current_name, _payload()))
                in_table = False
                table_rows = bytearray()
                table_lz = []
            table_lz = []
            current_name = _decode_utf16le(value)
        elif tag == _TAG_PARAM_VALUE and current_name is not None and not in_table:  # 0x0203
            pairs.append((current_name, value))
            current_name = None

        # --- Table name+begin tag ---
        # CONFIRMED (the parameter serializer): 0x0301 carries the
        # param name UTF-16LE as its value (new format — server uses writeRfcString
        # at).  Also accept legacy format where a preceding 0x0201 set the
        # name and 0x0301 is empty (begin marker only) — tolerates older captures.
        elif tag == _TAG_TABLE_NAME:  # 0x0301
            if in_table and current_name is not None:
                pairs.append((current_name, _payload()))
            if value:  # new format: name in 0x0301 value
                current_name = _decode_utf16le(value)
            # else: legacy format — name already set by preceding 0x0201; keep it
            in_table = True
            table_rows = bytearray()
            table_lz = []

        # --- BASXML-encoded table ---
        # An empty 0x3c02 brackets the block on both sides; the fragments between are
        # one XML document split at arbitrary points, so only the FIRST fragment names
        # the table. A later fragment may well start with '<item>', which is why the
        # name is taken once on entry rather than re-derived per chunk.
        elif tag == _TAG_BASXML_MARKER:
            basxml_current = None if basxml_current is not None else _BASXML_PENDING
        elif tag == _TAG_BASXML_DATA and basxml_current is not None:
            if basxml_current is _BASXML_PENDING:
                basxml_current = _basxml_open_tag(value) or _BASXML_PENDING
                if basxml_current is _BASXML_PENDING:
                    # Not plain-text XML — most likely the binary BASXML of issue #18.
                    # Say so rather than dropping the parameter without a word.
                    _logger.warning(
                        "an XML-encoded table could not be identified (payload starts "
                        "%r). If this is SAP's binary BASXML it is not supported yet — "
                        "see issue #18. The parameter is omitted from the result.",
                        bytes(value[:8]),
                    )
                    continue
                basxml_chunks.setdefault(basxml_current, [])
            basxml_chunks[basxml_current].append(value)

        # --- Table data tags ---
        elif tag == _TAG_TABLE_INFO and in_table:  # 0x0302
            pass  # row_size / row_count already available from row data length
        elif tag in (_TAG_TABLE_CONTENT, _TAG_TABLE_CONTENT_ALT) and in_table:  # 0x0303/0x0304
            # CONFIRMED: both tags carry raw uncompressed row bytes (the deserializer path)
            table_rows.extend(value)
        elif tag == _TAG_TABLE_CONTENT_LZ and in_table:  # 0x0305
            # One record is a fragment, never a self-contained block — collect and
            # decompress once the table ends (see decompress_table_stream).
            table_lz.append(value)
        elif tag == _TAG_TABLE_DELTA:  # 0x0335 — table identified by DM id
            if in_table and current_name is not None:
                pairs.append((current_name, _payload()))
            current_name = None
            table_rows = bytearray()
            table_lz = []
            in_table = False
            if len(value) >= 12:
                _, dm_id, _ = struct.unpack_from(">III", value, 0)
                name = (dm_table_names or {}).get(dm_id)
                if name is not None:
                    current_name = name
                    in_table = True
            # An unknown DM id means we cannot say which parameter this belongs to;
            # its rows are skipped rather than attached to the wrong name.
        elif (  # 0x0306 / 0x0336
            tag in (_TAG_TABLE_END, _TAG_TABLE_DELTA_END) and in_table and current_name is not None
        ):
            pairs.append((current_name, _payload()))
            current_name = None
            in_table = False
            table_rows = bytearray()
            table_lz = []

    # Finalize any unterminated table at end of stream
    if in_table and current_name is not None:
        pairs.append((current_name, _payload()))

    # BASXML tables are reported separately: their payload is XML text, not the flat
    # row buffer the binary encoding produces, so the caller must decode it with
    # decode_basxml_table rather than the codec.
    if basxml_out is not None:
        for name, chunks in basxml_chunks.items():
            basxml_out[name] = b"".join(chunks)

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
