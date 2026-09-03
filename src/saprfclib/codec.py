# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — ABAP type codec
#
# Sans-I/O encode/decode for the SAP RFC type system (the RFCTYPE enum). Two
# public dispatch functions keyed on the RFCTYPE integer (D-01):
#
#     encode(rfctype, value, field) -> bytes
#     decode(rfctype, data, field)  -> Any
#
# `field` is a FieldDesc (src/saprfclib/types.py) carrying the per-field metadata
# the codec needs — notably uc_length / nuc_length for fixed-width SAP_UC types
# and the unicode_mode flag that selects the uc_* vs nuc_* span (D-02 / D-09).
#
# Wire layouts are sourced from docs/protocol/serialization.md (the Phase 1 RE
# output). Confirmed-from-live-capture types: INT4/INT2/INT1, FLOAT, CHAR, DATE,
# TIME. confirmed via the type dispatch (GAP-B-03 closed): INT8=31,
# UTCLONG=32, UTCSECOND=33, UTCMINUTE=34, DTDAY=35, DTWEEK=36, DTMONTH=37,
# TSECOND=38, TMINUTE=39, CDAY=40 — all raw LE binary same path as INT4/INT2.
# STRING wire = UTF-8 bytes inside TLV (the UTF-8 string writer, SAP codepage 4110);
# XSTRING wire = raw bytes inside TLV. Neither type has an internal length prefix —
# the TLV header byte count is the length (confirmed 2026-07-05).
#
# SAP_UC encoding rule (CODEC-07 / threat T-02-05): UTF-16 with an explicit
# byte order only — "utf-16-le" in Unicode mode (the confirmed 4103 wire mode),
# "utf-16-be" otherwise. NEVER bare "utf-16": that codec emits/consumes a BOM
# the wire format does not use.
#
# Buffer handling (CODEC-06): decode accepts bytes | bytearray | memoryview and
# normalizes to bytes once up front so all type branches see a uniform buffer.
from __future__ import annotations

import struct
from decimal import Decimal
from typing import Any, cast

from saprfclib.exceptions import IncompleteDescriptorError
from saprfclib.types import FieldDesc, TypeDesc

__all__ = ["encode", "decode"]


# --------------------------------------------------------------------------- #
# RFCTYPE integer constants (SDK type definitions lines 91-125; values 31-40 confirmed
# from both header auto-increment and dispatch cases 0x1f-0x28).
# --------------------------------------------------------------------------- #
RFCTYPE_CHAR = 0
RFCTYPE_DATE = 1
RFCTYPE_BCD = 2
RFCTYPE_TIME = 3
RFCTYPE_BYTE = 4
RFCTYPE_TABLE = 5
RFCTYPE_NUM = 6
RFCTYPE_FLOAT = 7
RFCTYPE_INT = 8
RFCTYPE_INT2 = 9
RFCTYPE_INT1 = 10
RFCTYPE_NULL = 14
RFCTYPE_ABAPOBJECT = 16
RFCTYPE_STRUCTURE = 17
RFCTYPE_DECF16 = 23
RFCTYPE_DECF34 = 24
RFCTYPE_XMLDATA = 28
RFCTYPE_STRING = 29
RFCTYPE_XSTRING = 30
RFCTYPE_INT8 = 31
RFCTYPE_UTCLONG = 32
RFCTYPE_UTCSECOND = 33
RFCTYPE_UTCMINUTE = 34
RFCTYPE_DTDAY = 35
RFCTYPE_DTWEEK = 36
RFCTYPE_DTMONTH = 37
RFCTYPE_TSECOND = 38
RFCTYPE_TMINUTE = 39
RFCTYPE_CDAY = 40

# struct format chars for the fixed-width integer / float types. All multi-byte
# scalars are little-endian on the confirmed x86-64 wire (DATE/TIME excepted —
# those are SAP_UC text, not integers). FLOAT is an IEEE 754 double "<d".
# INT8/UTCLONG/UTCSECOND/UTCMINUTE share the INT8 8-byte group in the serializer
# (dispatch cases 7/0x1f-0x22); DTDAY-TSECOND share INT4 group (0x23-0x26);
# TMINUTE/CDAY share INT2 group (0x27-0x28). All confirmed LE by grouping.
# INT4 little-endian is CONFIRMED, not inferred: the STFC_CHANGING golden pair
# settles it by arithmetic. The request carries START_VALUE=0a000000 and
# COUNTER=01000000; the response carries RESULT=0b000000 and COUNTER=02000000. The
# function returns START_VALUE + COUNTER and increments COUNTER, so read
# little-endian that is 10 + 1 = 11 and 1 -> 2 — exactly right. Big-endian would make
# the inputs 167772160 and 16777216 and no reading of the response fits.
# Sources: tests/golden/framing/stfc_changing_request.bin / stfc_changing_response.bin
# (see tests/test_table_params.py::test_int4_params_are_little_endian_on_the_wire).
_INT_FORMATS: dict[int, str] = {
    RFCTYPE_INT: "<i",  # signed 32-bit
    RFCTYPE_INT2: "<h",  # signed 16-bit
    RFCTYPE_INT8: "<q",  # signed 64-bit (protocol analysis, same group as FLOAT=7)
    RFCTYPE_UTCLONG: "<q",  # 8-byte (protocol analysis
    RFCTYPE_UTCSECOND: "<q",  # protocol analysis
    RFCTYPE_UTCMINUTE: "<q",  # protocol analysis
    RFCTYPE_DTDAY: "<i",  # 4-byte (protocol analysis
    RFCTYPE_DTWEEK: "<i",  # protocol analysis
    RFCTYPE_DTMONTH: "<i",  # protocol analysis
    RFCTYPE_TSECOND: "<i",  # protocol analysis
    RFCTYPE_TMINUTE: "<h",  # 2-byte (protocol analysis
    RFCTYPE_CDAY: "<h",  # protocol analysis
}

# GAP-B-01 (DecFloat16/34) is CLOSED. Source: golden fixture
# tests/golden/serialization/decfloat_response.bin — a live capture from A4H
# (kernel 793) of a purpose-built remote-enabled function module returning nine
# known DECFLOAT values at both widths.
#
# The wire form is IEEE 754-2008 densely packed decimal, LITTLE-ENDIAN.
#
# Little-endian, not big-endian: this document previously recorded big-endian as
# "the neutral network form", which the capture disproves. Every one of the nine
# values decodes to its known value only after reversing the bytes, and encoding
# reproduces the captured bytes exactly. For example DECFLOAT16 42.0 arrives as
#     20 02 00 00 00 00 34 22
# and is 22 34 00 00 00 00 02 20 once reversed, which is 42.0 in DPD: coefficient
# 420, exponent -1.
#
# DPD is worth the table below rather than a shortcut: the coefficient is packed
# three decimal digits per ten bits, so the number twelve is 0x12 here where a
# binary-integer encoding would put 0x0c. That difference is what identified the
# scheme from a single captured value.
_DEFERRED: dict[int, str] = {}

# Per-width DPD parameters: (exponent-continuation bits, declets, exponent bias,
# coefficient digits). DECFLOAT16 is decimal64, DECFLOAT34 is decimal128.
_DECF_PARAMS: dict[int, tuple[int, int, int, int]] = {
    8: (8, 5, 398, 16),
    16: (12, 11, 6176, 34),
}


def _build_dpd_tables() -> tuple[dict[tuple[int, int, int], int], dict[int, tuple[int, int, int]]]:
    """Build the declet <-> three-digit maps from the IEEE 754-2008 encoding rules.

    Generated from the encoding rules rather than transcribed as a 1024-entry
    literal: the rules are eight cases keyed on the high bit of each digit, which
    is far easier to check by eye than a table of magic numbers. Several bit
    patterns decode to the same digits (the redundant encodings); the decode map
    keeps the first, and encoding always emits the canonical one.
    """
    encode_map: dict[tuple[int, int, int], int] = {}
    decode_map: dict[int, tuple[int, int, int]] = {}
    for d1 in range(10):
        for d2 in range(10):
            for d3 in range(10):
                a, b, c, d = (d1 >> 3) & 1, (d1 >> 2) & 1, (d1 >> 1) & 1, d1 & 1
                e, f, g, h = (d2 >> 3) & 1, (d2 >> 2) & 1, (d2 >> 1) & 1, d2 & 1
                i, j, k, m = (d3 >> 3) & 1, (d3 >> 2) & 1, (d3 >> 1) & 1, d3 & 1
                match (a << 2) | (e << 1) | i:
                    case 0b000:
                        pqr, stu, v, wxy = (b, c, d), (f, g, h), 0, (j, k, m)
                    case 0b001:
                        pqr, stu, v, wxy = (b, c, d), (f, g, h), 1, (0, 0, m)
                    case 0b010:
                        pqr, stu, v, wxy = (b, c, d), (j, k, h), 1, (0, 1, m)
                    case 0b011:
                        pqr, stu, v, wxy = (b, c, d), (1, 0, h), 1, (1, 1, m)
                    case 0b100:
                        pqr, stu, v, wxy = (j, k, d), (f, g, h), 1, (1, 0, m)
                    case 0b101:
                        pqr, stu, v, wxy = (f, g, d), (0, 1, h), 1, (1, 1, m)
                    case 0b110:
                        pqr, stu, v, wxy = (j, k, d), (0, 0, h), 1, (1, 1, m)
                    case _:
                        pqr, stu, v, wxy = (0, 0, d), (1, 1, h), 1, (1, 1, m)
                declet = 0
                for bit in (*pqr, *stu, v, *wxy):
                    declet = (declet << 1) | bit
                encode_map[(d1, d2, d3)] = declet
                decode_map.setdefault(declet, (d1, d2, d3))
    return encode_map, decode_map


_DPD_ENCODE, _DPD_DECODE = _build_dpd_tables()


def decode_decfloat(raw: bytes) -> Decimal:
    """Decode a DECFLOAT16 (8B) or DECFLOAT34 (16B) wire value.

    Source: tests/golden/serialization/decfloat_response.bin. Never `float` —
    that cannot hold a base-10 decimal exactly, which is the whole reason this
    type exists.
    """
    params = _DECF_PARAMS.get(len(raw))
    if params is None:
        raise ValueError(f"DECFLOAT value must be 8 or 16 bytes, got {len(raw)}")
    econ_bits, declets, bias, _ = params
    # The wire is little-endian; every IEEE field below is defined on the
    # big-endian form, so reverse once here and work in that orientation.
    value = int.from_bytes(raw[::-1], "big")
    total = len(raw) * 8
    sign = (value >> (total - 1)) & 1
    combo = (value >> (total - 6)) & 0x1F
    econ = (value >> (total - 6 - econ_bits)) & ((1 << econ_bits) - 1)

    # Combination field G0..G4 (IEEE 754-2008 section 3.5.2):
    #   11110 -> Infinity, 11111 -> NaN
    #   G0G1 = 11 -> leading digit 8+G4, exponent high bits G2G3
    #   otherwise -> leading digit G2G3G4, exponent high bits G0G1
    if (combo & 0b11110) == 0b11110:
        if combo & 1:
            return Decimal("-NaN") if sign else Decimal("NaN")
        return Decimal("-Infinity") if sign else Decimal("Infinity")
    if (combo >> 3) == 0b11:
        lead, exp_high = 8 + (combo & 1), (combo >> 1) & 0b11
    else:
        lead, exp_high = combo & 0b111, (combo >> 3) & 0b11

    exponent = ((exp_high << econ_bits) | econ) - bias
    coeff = value & ((1 << (total - 6 - econ_bits)) - 1)
    digits = [lead]
    for n in range(declets - 1, -1, -1):
        digits.extend(_DPD_DECODE[(coeff >> (n * 10)) & 0x3FF])
    return Decimal((sign, tuple(digits), exponent))


def encode_decfloat(value: Decimal | int | str, width: int) -> bytes:
    """Encode a value as DECFLOAT16 (width 8) or DECFLOAT34 (width 16).

    Round-trips the golden fixture byte-for-byte in both directions.
    """
    params = _DECF_PARAMS.get(width)
    if params is None:
        raise ValueError(f"DECFLOAT width must be 8 or 16, got {width}")
    econ_bits, declets, bias, ndigits = params

    if not isinstance(value, Decimal):
        value = Decimal(value)
    if value.is_nan():
        total = width * 8
        packed = ((1 if value.is_signed() else 0) << (total - 1)) | (0b11111 << (total - 6))
        return packed.to_bytes(width, "big")[::-1]
    if value.is_infinite():
        total = width * 8
        packed = ((1 if value.is_signed() else 0) << (total - 1)) | (0b11110 << (total - 6))
        return packed.to_bytes(width, "big")[::-1]

    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):  # pragma: no cover - guarded by is_nan/is_infinite
        raise ValueError(f"cannot encode special Decimal {value!r} as DECFLOAT")
    if len(digits) > ndigits:
        raise ValueError(
            f"{value} has {len(digits)} significant digits; DECFLOAT{ndigits} holds {ndigits}"
        )
    biased = exponent + bias
    if not 0 <= biased <= (3 << econ_bits) - 1:
        raise ValueError(f"exponent {exponent} is outside the DECFLOAT{ndigits} range")

    padded = (0,) * (ndigits - len(digits)) + tuple(digits)
    lead = padded[0]
    exp_high = biased >> econ_bits
    if lead <= 7:
        combo = (exp_high << 3) | lead
    else:
        combo = 0b11000 | (exp_high << 1) | (lead & 1)
    coeff = 0
    for n in range(declets):
        trio = padded[1 + n * 3 : 4 + n * 3]
        coeff = (coeff << 10) | _DPD_ENCODE[(trio[0], trio[1], trio[2])]

    total = width * 8
    packed = (
        (sign << (total - 1))
        | (combo << (total - 6))
        | ((biased & ((1 << econ_bits) - 1)) << (total - 6 - econ_bits))
        | coeff
    )
    return packed.to_bytes(width, "big")[::-1]


# Types the SAP SDK documents as not serialized on the wire.
_OUT_OF_SCOPE = frozenset({RFCTYPE_NULL, RFCTYPE_ABAPOBJECT, RFCTYPE_XMLDATA})

# Byte-like types whose "unset" value is empty bytes rather than an empty string.
_BYTE_LIKE_TYPES = frozenset({RFCTYPE_BYTE, RFCTYPE_XSTRING})


def _default_field_value(child: FieldDesc) -> Any:
    """Return the initial value for a structure field the caller left unset.

    ABAP initialises every field of a work area before an RFC fills it, so a
    caller supplying only the fields they care about is the normal case — most
    SAP function modules are written expecting it (RFC_READ_TABLE's FIELDS rows
    are the canonical example: callers set FIELDNAME and nothing else).

    The value is chosen so the type's own encoder produces the correct padding
    rather than leaving the buffer's NUL fill in place: CHAR pads with blanks and
    NUM pads with zeros (Pitfall: fixed-width character fields are blank-padded,
    numeric fields zero-padded — the two are not interchangeable), so both start
    from an empty string and let ``_encode_uc_fixed`` do the padding.
    """
    rfctype = child.rfctype
    if rfctype == RFCTYPE_STRUCTURE:
        return {}
    if rfctype == RFCTYPE_TABLE:
        return []
    if rfctype in _BYTE_LIKE_TYPES:
        return b""
    if rfctype == RFCTYPE_FLOAT:
        return 0.0
    if rfctype == RFCTYPE_BCD:
        return Decimal(0)
    if rfctype in _INT_FORMATS or rfctype == RFCTYPE_INT1:
        return 0
    # CHAR / DATE / TIME / NUM / STRING and anything else character-shaped.
    return ""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _as_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Normalize any buffer-protocol input to bytes (CODEC-06)."""
    if isinstance(data, bytes):
        return data
    return bytes(data)


def _uc_encoding(field: FieldDesc) -> str:
    """SAP_UC codec name — explicit LE/BE only (CODEC-07).

    Unicode mode is the confirmed 4103 wire mode (UTF-16-LE); the BE codec
    covers the negotiated big-endian variant. A bare BOM-bearing codec is
    forbidden — see the module header.
    """
    return "utf-16-le" if field.unicode_mode else "utf-16-be"


def _field_span(field: FieldDesc) -> tuple[int, int]:
    """Return (offset, length) for the active layout.

    Unicode mode selects the uc_* span; otherwise the nuc_* span. Only the uc_*
    branch is reachable over a live connection: the session refuses a codepage
    other than 4103 at logon, so a non-Unicode application server never gets as
    far as a field decode (D-09). The nuc_* branch stays because a FieldDesc can
    be built by hand and the descriptor carries both spans.
    """
    if field.unicode_mode:
        return field.uc_offset, field.uc_length
    return field.nuc_offset, field.nuc_length


def _char_count(field: FieldDesc) -> int:
    """Fixed SAP_UC field width in *characters* (Pitfall 1 — width is chars).

    The character count is a property of the field, independent of wire byte
    order, so it is always uc_length // 2 (uc_length is the UTF-16 byte width).
    Only the encoding (LE vs BE) varies with unicode_mode, not the char count.
    """
    return field.uc_length // 2


def _decode_uc_fixed(data: bytes, field: FieldDesc) -> str:
    """Decode a fixed-width SAP_UC field (CHAR/NUM/DATE/TIME)."""
    return data.decode(_uc_encoding(field))


def _encode_uc_fixed(value: str, field: FieldDesc, *, pad: str) -> bytes:
    """Encode a fixed-width SAP_UC field, padding to the field's char width.

    `pad` is the pad character: a space for CHAR, "0" for NUM. The width is the
    field's byte length // 2 (Pitfall 1 — width is in characters, not bytes).
    """
    char_width = _char_count(field)
    enc = _uc_encoding(field)
    if char_width:
        if pad == "0":
            text = value.rjust(char_width, "0")
        else:
            text = value.ljust(char_width, pad)
        text = text[:char_width]
    else:
        text = value
    return text.encode(enc)


# --------------------------------------------------------------------------- #
# BCD packed decimals (CODEC-02) — decimal.Decimal value, in-tree nibble codec
# --------------------------------------------------------------------------- #
#
# Wire form (live-confirmed from BAPISFLIGHT.PRICE, P15.2 = 800000.50,
# 00 00 00 08 00 00 05 0C; GAP-B-02 closed): packed BCD, two decimal digits per
# byte (high nibble then low nibble), big-end first. The LAST byte's low nibble
# is the sign nibble, NOT a digit. Total wire width = ceil((precision + 1) / 2)
# bytes, so the digit count is (width * 2 - 1) — derived directly from the
# field's declared byte span, no separate precision field needed.
#
# Sign nibbles (SDK type definitions SAP_BCD; Pitfall 4): 0x0C / 0x0F / 0x0B → positive,
# 0x0D → negative on DECODE; ENCODE emits only the canonical 0x0C (non-negative)
# or 0x0D (negative). The value is modelled with decimal.Decimal exclusively —
# NEVER float — for exact base-10 financial correctness (D-13).
#
# Security (threat T-02-09 / T-02-11): the buffer length is validated against the
# descriptor-declared width before parsing, and every digit nibble must be 0-9
# (a value > 9 in a digit position is a malformed packed-BCD byte) — a typed
# ValueError is raised rather than producing silent garbage.

_BCD_POSITIVE_SIGNS = frozenset({0x0C, 0x0F, 0x0B})
_BCD_NEGATIVE_SIGN = 0x0D


def _bcd_width(field: FieldDesc) -> int:
    """The BCD wire byte width for the active layout (uc_* vs nuc_*)."""
    _, length = _field_span(field)
    return length


def _decode_bcd(data: bytes, field: FieldDesc) -> Decimal:
    """Decode packed BCD into a ``decimal.Decimal`` (never float).

    Reads nibbles high-then-low across the bytes; the final low nibble is the
    sign (0x0D → negative; 0x0C/0x0F/0x0B → positive). Assembles the digit string
    and scales by ``-field.decimals``. Rejects a short buffer and any non-digit
    nibble in a digit position (threat T-02-09 / T-02-11).
    """
    width = _bcd_width(field)
    if width <= 0:
        raise ValueError(f"BCD field width must be positive, got {width}")
    if len(data) < width:
        raise ValueError(f"BCD field truncated: need {width} bytes, have {len(data)}")
    span = data[:width]

    nibbles: list[int] = []
    for byte in span:
        nibbles.append(byte >> 4)
        nibbles.append(byte & 0x0F)

    sign_nibble = nibbles.pop()
    if sign_nibble == _BCD_NEGATIVE_SIGN:
        negative = True
    elif sign_nibble in _BCD_POSITIVE_SIGNS:
        negative = False
    else:
        raise ValueError(f"invalid BCD sign nibble 0x{sign_nibble:X}")

    for n in nibbles:
        if n > 9:
            raise ValueError(f"invalid BCD digit nibble 0x{n:X}")

    digits = "".join(str(n) for n in nibbles) or "0"
    unscaled = Decimal(f"{'-' if negative else ''}{digits}")
    return unscaled.scaleb(-field.decimals)


def _encode_bcd(value: Decimal, field: FieldDesc) -> bytes:
    """Encode a ``decimal.Decimal`` into packed BCD bytes (never float).

    Scales the value to ``field.decimals`` integer digits, zero-pads to the
    field's full digit count (``width * 2 - 1``), appends the canonical sign
    nibble (0x0D negative else 0x0C) as the final low nibble, and packs two
    nibbles per byte big-end first into ``width`` bytes.
    """
    if not isinstance(value, Decimal):
        # Accept ints/strings but NEVER a float (binary float corrupts base-10).
        if isinstance(value, float):
            raise TypeError("BCD value must be Decimal, not float (D-13)")
        value = Decimal(value)

    width = _bcd_width(field)
    if width <= 0:
        raise ValueError(f"BCD field width must be positive, got {width}")
    digit_count = width * 2 - 1

    negative = value.as_tuple().sign == 1
    # Unscaled integer = value * 10**decimals, exact in Decimal. Convert to a
    # plain Python int so the digit string never carries an exponent suffix
    # (e.g. Decimal('0').scaleb(2) renders as '0E+2') — int() collapses it.
    unscaled = int(value.scaleb(field.decimals).to_integral_value())
    digit_str = str(abs(unscaled))
    if len(digit_str) > digit_count:
        raise ValueError(
            f"BCD value {value} needs {len(digit_str)} digits but field holds {digit_count}"
        )
    digit_str = digit_str.rjust(digit_count, "0")

    sign_nibble = _BCD_NEGATIVE_SIGN if negative else 0x0C
    nibbles = [int(c) for c in digit_str] + [sign_nibble]

    out = bytearray(width)
    for i in range(width):
        out[i] = (nibbles[2 * i] << 4) | nibbles[2 * i + 1]
    return bytes(out)


# --------------------------------------------------------------------------- #
# STRUCTURE / TABLE — descriptor-driven, arbitrary-depth recursion (D-08)
# --------------------------------------------------------------------------- #
#
# A STRUCTURE decodes to dict[str, Any] (D-13); a TABLE to list[dict] of
# fixed-size rows. Each field is positioned at its uc_* span when unicode_mode
# else its nuc_* span (D-09), and every leaf is decoded by the same scalar
# dispatch used for top-level values — so recursion bottoms out automatically.
# STRUCTURE-in-STRUCTURE and TABLE-in-STRUCTURE recurse with NO depth limit.
#
# Security: each field span is bounds-checked (offset + length <= len(data))
# before slicing (threat T-02-07 — no over-read). TABLE rows are derived from
# len(data) // row_size (bounded by the actual buffer) and sliced lazily over a
# memoryview, never pre-allocated from an attacker-controlled count (T-02-06).


def _row_size(type_desc: TypeDesc, unicode_mode: bool) -> int:
    """Fixed per-row / per-structure byte size for the active layout."""
    return type_desc.uc_size if unicode_mode else type_desc.nuc_size


def _decode_structure(
    data: bytes | bytearray | memoryview,
    type_desc: TypeDesc,
    unicode_mode: bool,
) -> dict[str, Any]:
    """Decode a descriptor-driven STRUCTURE into a dict (D-08 / D-13).

    Iterates ``type_desc.fields``, slices each field's (offset, length) span for
    the active Unicode/non-Unicode layout, and dispatches each leaf through the
    same per-type machinery — recursing into nested STRUCTURE/TABLE fields.
    """
    result: dict[str, Any] = {}
    for child in type_desc.fields:
        # Propagate the active layout onto each child so nested spans resolve.
        child.unicode_mode = unicode_mode
        offset, length = _field_span(child)
        if offset + length > len(data):
            raise ValueError(
                f"STRUCTURE field {child.name!r} span [{offset}:{offset + length}] "
                f"exceeds buffer length {len(data)}"
            )
        span = data[offset : offset + length]
        if child.rfctype == RFCTYPE_STRUCTURE:
            result[child.name] = _decode_structure(
                span, _require_type_desc(child, "decode"), unicode_mode
            )
        elif child.rfctype == RFCTYPE_TABLE:
            result[child.name] = _decode_table(span, child)
        else:
            result[child.name] = decode(child.rfctype, span, child)
    return result


def _decode_table(
    data: bytes | bytearray | memoryview,
    field: FieldDesc,
) -> list[dict[str, Any]]:
    """Decode a TABLE into a list of row dicts via zero-copy memoryview slices.

    Row count is ``len(data) // row_size`` — bounded by the actual buffer, never
    by an attacker-controlled count (threat T-02-06). Each row is decoded as a
    STRUCTURE over its memoryview slice (Pattern 3, D-11 zero-copy).
    """
    type_desc = _require_type_desc(field, "decode")
    row_size = _row_size(type_desc, field.unicode_mode)
    if row_size <= 0:
        raise ValueError(f"TABLE row size must be positive, got {row_size}")
    mv = memoryview(_as_bytes(data))
    return [
        _decode_structure(mv[i : i + row_size], type_desc, field.unicode_mode)
        for i in range(0, len(mv) - row_size + 1, row_size)
    ]


def _require_type_desc(field: FieldDesc, action: str) -> TypeDesc:
    """Return the field's layout, or explain precisely what is missing.

    A STRUCTURE or TABLE field cannot be encoded or decoded without the layout of
    its row, which the client fetches separately via RFC_GET_STRUCTURE_DEFINITION.
    When that lookup fails the descriptor arrives with ``type_desc=None`` and the
    failure used to surface here as a bare AssertionError naming nothing — no field,
    no structure, no cause. Say which parameter and which DDIC type are missing so
    the real problem is findable.
    """
    if field.type_desc is None:
        kind = "TABLE" if field.rfctype == RFCTYPE_TABLE else "STRUCTURE"
        raise IncompleteDescriptorError(
            f"cannot {action} {kind} parameter {field.name!r}: its row layout was "
            f"never resolved (type_desc is None). The RFC_GET_STRUCTURE_DEFINITION "
            f"lookup for its DDIC type did not complete."
        )
    return field.type_desc


def _encode_structure(
    value: dict[str, Any],
    type_desc: TypeDesc,
    unicode_mode: bool,
) -> bytes:
    """Encode a dict back into a fixed-size STRUCTURE buffer (inverse of decode).

    Lays each child field's encoding at its declared offset into a bytearray
    sized to the layout's total byte size, zero-padding any gaps. Recurses for
    nested STRUCTURE; nested TABLE fields encode to their full variable extent
    (the descriptor's row size bounds a single embedded row in Phase 2 tests).

    Fields absent from ``value`` are filled with their type's initial value via
    ``_default_field_value`` and encoded normally, so a partial row dict yields a
    correctly padded work area instead of raising KeyError or leaving NUL fill
    where the wire expects blanks.
    """
    size = _row_size(type_desc, unicode_mode)
    buf = bytearray(size)
    for child in type_desc.fields:
        child.unicode_mode = unicode_mode
        offset, _ = _field_span(child)
        if child.name in value:
            child_value = value[child.name]
        else:
            if child.rfctype in (RFCTYPE_STRUCTURE, RFCTYPE_TABLE) and child.type_desc is None:
                # No layout to lay out, and the caller supplied nothing: the
                # zero fill already in ``buf`` is the initial value. Encoding a
                # supplied value without a type_desc still asserts below.
                continue
            child_value = _default_field_value(child)
        if child.rfctype == RFCTYPE_STRUCTURE:
            raw = _encode_structure(child_value, _require_type_desc(child, "encode"), unicode_mode)
        elif child.rfctype == RFCTYPE_TABLE:
            raw = _encode_table(child_value, child)
        else:
            raw = encode(child.rfctype, child_value, child)
        end = offset + len(raw)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[offset:end] = raw
    return bytes(buf)


def _encode_table(value: list[dict[str, Any]], field: FieldDesc) -> bytes:
    """Encode a list of row dicts into a concatenated TABLE buffer.

    No row delimiter — rows are fixed-size structures back-to-back (D-10).
    """
    type_desc = _require_type_desc(field, "encode")
    out = bytearray()
    for row in value:
        out += _encode_structure(row, type_desc, field.unicode_mode)
    return bytes(out)


# --------------------------------------------------------------------------- #
# decode
# --------------------------------------------------------------------------- #


def decode(rfctype: int, data: bytes | bytearray | memoryview, field: FieldDesc) -> Any:
    """Decode wire bytes into a Python value for the given RFCTYPE.

    Args:
        rfctype (int): The RFCTYPE constant identifying the ABAP data type
            (RFCTYPE_CHAR, RFCTYPE_INT, etc.). See saprfclib.types for the full
            set of constants.
        data (bytes | bytearray | memoryview): Raw wire bytes to decode. All
            three buffer types are accepted without copying (CODEC-06).
        field (FieldDesc): Descriptor carrying unicode_mode, nuc_offset/
            nuc_length, uc_offset/uc_length, decimals, and type_desc. Used for
            STRUCTURE/TABLE layout and BCD precision.

    Returns:
        Python-native type corresponding to the RFCTYPE — str for
        CHAR/NUM/DATE/TIME/STRING, bytes for BYTE/XSTRING, int for
        INT1/INT2/INT4/INT8 and all temporal extension types, float for FLOAT,
        decimal.Decimal for BCD, dict for STRUCTURE, list[dict] for TABLE.

    Raises:
        ValueError: If rfctype is out-of-scope or unknown.
        NotImplementedError: For deferred types.
    """
    buf = _as_bytes(data)

    if rfctype in _OUT_OF_SCOPE:
        raise ValueError(f"unsupported RFCTYPE {rfctype}")
    if rfctype in _DEFERRED:
        raise NotImplementedError(
            f"RFCTYPE {rfctype} decode not yet implemented — see {_DEFERRED[rfctype]}"
        )
    if rfctype in (RFCTYPE_DECF16, RFCTYPE_DECF34):
        return decode_decfloat(bytes(buf))

    match rfctype:
        case _ if rfctype in _INT_FORMATS:
            fmt = _INT_FORMATS[rfctype]
            (value,) = struct.unpack(fmt, buf[: struct.calcsize(fmt)])
            return value
        case rfctype if rfctype == RFCTYPE_BCD:
            return _decode_bcd(buf, field)
        case rfctype if rfctype == RFCTYPE_INT1:
            return buf[0]  # unsigned single byte
        case rfctype if rfctype == RFCTYPE_FLOAT:
            (value,) = struct.unpack("<d", buf[:8])
            return value
        case rfctype if rfctype == RFCTYPE_CHAR:
            return _decode_uc_fixed(buf, field).rstrip(" ")
        case rfctype if rfctype == RFCTYPE_NUM:
            return _decode_uc_fixed(buf, field)
        case rfctype if rfctype == RFCTYPE_DATE:
            return _decode_uc_fixed(buf, field)  # str "YYYYMMDD" — NOT datetime (D-13)
        case rfctype if rfctype == RFCTYPE_TIME:
            return _decode_uc_fixed(buf, field)  # str "HHMMSS" — NOT time (D-13)
        case rfctype if rfctype == RFCTYPE_BYTE:
            return buf
        case rfctype if rfctype == RFCTYPE_STRING:
            return buf.decode("utf-8")
        case rfctype if rfctype == RFCTYPE_XSTRING:
            return buf
        case rfctype if rfctype == RFCTYPE_STRUCTURE:
            return _decode_structure(buf, _require_type_desc(field, "decode"), field.unicode_mode)
        case rfctype if rfctype == RFCTYPE_TABLE:
            return _decode_table(buf, field)
        case _:
            raise ValueError(f"unknown RFCTYPE {rfctype}")


# --------------------------------------------------------------------------- #
# encode
# --------------------------------------------------------------------------- #


def encode(rfctype: int, value: Any, field: FieldDesc) -> bytes:
    """Encode a Python value into wire bytes for the given RFCTYPE.

    Args:
        rfctype (int): The RFCTYPE constant identifying the ABAP data type.
        value (Any): Python-native value to encode. Type must match the
            RFCTYPE: str for character types, int for integer types,
            decimal.Decimal for BCD, bytes for BYTE/XSTRING, dict for
            STRUCTURE, list[dict] for TABLE.
        field (FieldDesc): Descriptor carrying layout, precision, and
            type_desc. Same as decode().

    Returns:
        bytes: The wire representation of value for this RFCTYPE and field
        descriptor.

    Raises:
        ValueError: For out-of-scope or unknown rfctype.
        NotImplementedError: For deferred types.
        ValueError: For a DECFLOAT value that does not fit the target width.
        TypeError: If value is the wrong Python type for the rfctype.
    """
    if rfctype in _OUT_OF_SCOPE:
        raise ValueError(f"unsupported RFCTYPE {rfctype}")
    if rfctype in _DEFERRED:
        raise NotImplementedError(
            f"RFCTYPE {rfctype} encode not yet implemented — see {_DEFERRED[rfctype]}"
        )
    if rfctype in (RFCTYPE_DECF16, RFCTYPE_DECF34):
        return encode_decfloat(
            cast("Decimal | int | str", value), 8 if rfctype == RFCTYPE_DECF16 else 16
        )

    match rfctype:
        case _ if rfctype in _INT_FORMATS:
            return struct.pack(_INT_FORMATS[rfctype], int(value))
        case rfctype if rfctype == RFCTYPE_BCD:
            return _encode_bcd(value, field)
        case rfctype if rfctype == RFCTYPE_INT1:
            iv = int(value)
            if not 0 <= iv <= 0xFF:
                raise ValueError(f"INT1 out of range: {iv}")
            return bytes((iv,))
        case rfctype if rfctype == RFCTYPE_FLOAT:
            return struct.pack("<d", float(value))
        case rfctype if rfctype == RFCTYPE_CHAR:
            return _encode_uc_fixed(value, field, pad=" ")
        case rfctype if rfctype == RFCTYPE_NUM:
            return _encode_uc_fixed(value, field, pad="0")
        case rfctype if rfctype == RFCTYPE_DATE:
            return _encode_uc_fixed(value, field, pad=" ")
        case rfctype if rfctype == RFCTYPE_TIME:
            return _encode_uc_fixed(value, field, pad=" ")
        case rfctype if rfctype == RFCTYPE_BYTE:
            return bytes(value)
        case rfctype if rfctype == RFCTYPE_STRING:
            return cast(bytes, value.encode("utf-8"))
        case rfctype if rfctype == RFCTYPE_XSTRING:
            return bytes(value)
        case rfctype if rfctype == RFCTYPE_STRUCTURE:
            return _encode_structure(value, _require_type_desc(field, "encode"), field.unicode_mode)
        case rfctype if rfctype == RFCTYPE_TABLE:
            return _encode_table(value, field)
        case _:
            raise ValueError(f"unknown RFCTYPE {rfctype}")
