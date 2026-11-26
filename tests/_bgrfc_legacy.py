# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The inbound bgRFC frame RfcServer parses: a test-only builder, not SAP's format.

Until #34 the client sent bgRFC units in this shape: the unit id and type as named
CHAR parameters and each call as raw bytes under BGRFC_CALL_<n>. A real server
refuses it -- the client now sends what the reference client does
(invoke.build_bgrfc_sdata). RfcServer's inbound bgRFC path still reads this shape,
because how an ABAP system sends a bgRFC unit to a registered server has not been
captured (docs/protocol/trfc.md, Known Gaps). These tests keep exercising that
path's bookkeeping -- persist before execute, dedup, state -- against frames built
here, and say nothing about the wire.
"""

from __future__ import annotations

from saprfclib.invoke import (
    _BGRFC_DEST_SHIP,
    _RFC_VERSION,
    _TAG_CALL_START,
    _TAG_FUNC_NAME,
    _TAG_PARAM_NAME,
    _TAG_PARAM_SECTION,
    _TAG_PARAM_VALUE,
    _TAG_RFC_VERSION,
    _TAG_TERMINATOR,
    _UNIT_TYPE_Q,
    _UNIT_TYPE_T,
    _validate_unit_id,
    tlv_record,
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
