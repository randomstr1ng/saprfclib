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

import datetime as _dt
import re
import struct
from decimal import Decimal
from typing import Any, cast

from saprfclib.exceptions import IncompleteDescriptorError
from saprfclib.types import FieldDesc, TypeDesc

__all__ = ["encode", "decode"]


# --------------------------------------------------------------------------- #
# RFCTYPE integer constants: the library's numbering of the types. On the wire the
# metadata names a type by its EXID character (metadata._EXID_TO_RFCTYPE); the numbers
# match the NW RFC SDK's public RFCTYPE values. INT8 (31) and UTCLONG (32) are captured
# (tests/golden/serialization/int8_utclong.json); 33-40 are [ASSUMED], see
# docs/protocol/serialization.md [A1].
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
# INT8 is CONFIRMED: signed 64-bit little-endian. A purpose-built function module
# returned 0x0102030405060708 as 08 07 06 05 04 03 02 01 and -81985529216486896 as
# 10 32 54 76 98 ba dc fe, and the reference client sent -2 as fe ff .. ff
# (tests/golden/serialization/int8_utclong.json, live 2026-11-12).
# UTCLONG has its own encoding, see _encode_utclong.
# Types 33-40: [ASSUMED] little-endian integers of 8 (UTCSECOND, UTCMINUTE), 4 (DTDAY,
# DTWEEK, DTMONTH, TSECOND) or 2 (TMINUTE, CDAY) bytes, by analogy with INT/INT2/INT8.
# Kernel 793's dictionary has no data type for any of them (domain DATATYPE lists
# INT8, UTCL, DATN, TIMN but none of these), so no RFC interface on that release can
# carry one; a release that has them, and a function module using them, would settle it.
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
    RFCTYPE_INT8: "<q",  # signed 64-bit, confirmed above
    RFCTYPE_UTCSECOND: "<q",  # [ASSUMED]
    RFCTYPE_UTCMINUTE: "<q",  # [ASSUMED]
    RFCTYPE_DTDAY: "<i",  # [ASSUMED]
    RFCTYPE_DTWEEK: "<i",  # [ASSUMED]
    RFCTYPE_DTMONTH: "<i",  # [ASSUMED]
    RFCTYPE_TSECOND: "<i",  # [ASSUMED]
    RFCTYPE_TMINUTE: "<h",  # [ASSUMED]
    RFCTYPE_CDAY: "<h",  # [ASSUMED]
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


# Types this library does not serialize: no capture carries one, and no function module
# seen exposes one as a parameter.
_OUT_OF_SCOPE = frozenset({RFCTYPE_NULL, RFCTYPE_ABAPOBJECT, RFCTYPE_XMLDATA})

# Byte-like types whose "unset" value is empty bytes rather than an empty string.
_BYTE_LIKE_TYPES = frozenset({RFCTYPE_BYTE, RFCTYPE_XSTRING})


# --------------------------------------------------------------------------- #
# UTCLONG
# --------------------------------------------------------------------------- #
#
# UTCLONG travels as an 8-byte little-endian integer: 0 is the initial value, and
# otherwise it is 1 + the number of 100-nanosecond units since 0001-01-01T00:00:00 on
# the calendar in force -- Julian before 1582-10-15, Gregorian from then on. The days
# 1582-10-05 .. 1582-10-14 do not exist. Source: live 2026-11-12, a purpose-built
# function module echoing UTCLONG values from the reference client, eleven values
# from 0001-01-01 to 9999-12-31 including 1000-06-15, 1582-10-04, 1582-10-15 and
# 0004-02-29 (tests/golden/serialization/int8_utclong.json). The reference client
# refuses the reform gap, and writes values as YYYY-MM-DDTHH:MM:SS.fffffff; a
# trailing Z is accepted.

_UTCLONG_EPOCH_JDN = 1721424  # Julian day number of Julian 0001-01-01
_GREGORIAN_JDN = 2299161  # 1582-10-15, the first Gregorian day
_TICKS_PER_DAY = 86_400 * 10**7


def _jdn(y: int, m: int, d: int) -> int:
    a = (14 - m) // 12
    y2, m2 = y + 4800 - a, m + 12 * a - 3
    base = d + (153 * m2 + 2) // 5 + 365 * y2 + y2 // 4
    if (y, m, d) >= (1582, 10, 15):
        return base - y2 // 100 + y2 // 400 - 32045
    return base - 32083


def _from_jdn(j: int) -> tuple[int, int, int]:
    if j >= _GREGORIAN_JDN:
        a = j + 32044
        b = (4 * a + 3) // 146097
        c = a - 146097 * b // 4
    else:
        b = 0
        c = j + 32082
    d = (4 * c + 3) // 1461
    e = c - 1461 * d // 4
    m = (5 * e + 2) // 153
    return 100 * b + d - 4800 + m // 10, m + 3 - 12 * (m // 10), e - (153 * m + 2) // 5 + 1


def _encode_utclong(value: Any) -> bytes:
    if value is None or value == "":
        return bytes(8)
    if isinstance(value, _dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(_dt.UTC).replace(tzinfo=None)
        y, mo, d = value.year, value.month, value.day
        h, mi, s, frac = value.hour, value.minute, value.second, value.microsecond * 10
    else:
        m = re.fullmatch(
            r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?Z?", str(value)
        )
        if m is None:
            raise ValueError(f"UTCLONG value {value!r} is not YYYY-MM-DDTHH:MM:SS[.fffffff][Z]")
        y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
        frac = int((m.group(7) or "0").ljust(7, "0"))
    if (1582, 10, 5) <= (y, mo, d) <= (1582, 10, 14):
        raise ValueError(f"UTCLONG date {y:04d}-{mo:02d}-{d:02d} is in the 1582 calendar gap")
    if not (1 <= y <= 9999 and 1 <= mo <= 12 and h < 24 and mi < 60 and s < 60):
        raise ValueError(f"UTCLONG value {value!r} is out of range")
    j = _jdn(y, mo, d)
    if _from_jdn(j) != (y, mo, d):
        raise ValueError(f"UTCLONG date {y:04d}-{mo:02d}-{d:02d} does not exist")
    days = j - _UTCLONG_EPOCH_JDN
    ticks = (days * 86_400 + h * 3600 + mi * 60 + s) * 10**7 + frac
    return struct.pack("<q", ticks + 1)


def _decode_utclong(buf: bytes) -> str | None:
    (raw,) = struct.unpack("<q", buf[:8])
    if raw == 0:
        return None
    days, rest = divmod(raw - 1, _TICKS_PER_DAY)
    y, mo, d = _from_jdn(days + _UTCLONG_EPOCH_JDN)
    secs, frac = divmod(rest, 10**7)
    h, r = divmod(secs, 3600)
    mi, s = divmod(r, 60)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{frac:07d}"


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
    if rfctype == RFCTYPE_UTCLONG:
        return None
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


def _decode_initial_or(value: str) -> str:
    """Map an ABAP initial DATE/TIME (all zeros or all blanks) to "", else keep it.

    The wire never carries an empty DATS/TIMS; an unset one is all '0' (or, less
    often, all blank). The reference client reports that as "" so callers can tell
    "no date" from a real value, and matching it keeps decoded results identical.
    A real date such as "20260930" contains a non-zero, non-blank character and is
    returned unchanged.
    """
    return "" if not value.strip("0 ") else value


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
# Sign nibbles (Pitfall 4): 0x0C for zero and positive values and 0x0D for negative ones,
# both ways -- live capture of a purpose-built function module, the reference client
# sending and the server returning both signs (tests/golden/serialization/bcd_sign.json).
# DECODE also reads 0x0F and 0x0B as positive [ASSUMED]: tolerated, never seen. The value is modelled with decimal.Decimal exclusively —
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
# before slicing (threat T-02-07 — no over-read). The TABLE row width is
# len(data) // row_count (see _decode_table, bounded by the actual buffer) and rows
# are sliced lazily over a
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
    row_count: int | None = None,
) -> list[dict[str, Any]]:
    """Decode a TABLE into a list of row dicts via zero-copy memoryview slices.

    The row width is ``len(data) // row_count`` — measured from what the server
    actually sent, divided by how many rows it said it sent. Each row is decoded
    as a STRUCTURE over its memoryview slice (Pattern 3, D-11 zero-copy).

    Neither obvious source for the width is usable, because the same DDIC row
    type reaches the client at two widths:

    * ``TypeDesc.uc_size`` is the structure's padded width (the end of its last
      field rounded up to its alignment, as the reference client sends rows).
      The server's uncompressed 0x0303 path packs rows to the end of the last
      field; the compressed 0x0305 path pads them. RFC_FUNINT is 402 packed and
      404 padded.
    * ``0x0302``'s ``row_size`` reports the padded width on **both** paths. It
      carries the DDIC layout width and does not track how the rows were
      actually serialized.

    So each is right on one path and wrong on the other, and picking either moves
    the bug rather than fixing it: splitting a 404-wide buffer by 402, or a
    402-wide buffer by 404, does not raise. It yields the right *number* of
    row-shaped slices, each drifting further out of alignment than the last,
    until names are eaten from the end.

    ``row_count`` is different in kind. It counts things the server actually
    sent, so it cannot disagree with the serializer, and the width falls out of
    the buffer it produced.

    A row may be as narrow as the end of the last field (packed), never
    narrower.

    Falls back to the descriptor width when no count is available, which keeps
    hand-built descriptors and the encode path working.
    """
    type_desc = _require_type_desc(field, "decode")
    declared = _row_size(type_desc, field.unicode_mode)
    length = len(_as_bytes(data)) if not isinstance(data, memoryview) else len(data)
    # The narrowest row the layout fits in: the end of its last field.
    ends = []
    for child in type_desc.fields:
        child.unicode_mode = field.unicode_mode
        ends.append(sum(_field_span(child)))
    minimum = min(declared, max(ends)) if ends else declared

    if row_count is None or row_count <= 0:
        # No count to divide by: an absent 0x0302, a synthetic descriptor, or an
        # empty table. An empty buffer with no rows is not an error.
        if length == 0:
            return []
        row_size = declared
    else:
        if length % row_count:
            # Every row is the same width, so a remainder means one of the two
            # numbers is not what it claims. Refusing beats rounding it away and
            # decoding rows that are quietly misaligned.
            raise ValueError(
                f"TABLE {field.name!r}: {length} bytes does not divide into the "
                f"{row_count} rows the server declared (remainder "
                f"{length % row_count}); refusing to guess the row width"
            )
        row_size = length // row_count
        if row_size < minimum:
            # The width is derived from peer-supplied numbers and becomes a slice
            # length, so it sits on the same trust boundary as T-02-06. A row
            # narrower than the layout cannot be decoded -- every field past the
            # cut would read from the next row.
            raise ValueError(
                f"TABLE {field.name!r}: {length} bytes over {row_count} rows gives "
                f"a {row_size}-byte row, narrower than the {minimum}-byte layout "
                "its descriptor requires; refusing to decode misaligned bytes"
            )
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


def decode(
    rfctype: int,
    data: bytes | bytearray | memoryview,
    field: FieldDesc,
    row_count: int | None = None,
) -> Any:
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
        case rfctype if rfctype == RFCTYPE_UTCLONG:
            return _decode_utclong(bytes(buf))
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
            # str "YYYYMMDD" — NOT datetime (D-13). The ABAP initial date is all
            # zeros (or all blanks); the reference client (pyrfc) surfaces that as
            # "" rather than "00000000", so a caller can tell "no date" from a real
            # one. Match that: only an all-zero/all-blank field becomes "".
            return _decode_initial_or(_decode_uc_fixed(buf, field))
        case rfctype if rfctype == RFCTYPE_TIME:
            return _decode_initial_or(_decode_uc_fixed(buf, field))  # "HHMMSS" (D-13)
        case rfctype if rfctype == RFCTYPE_BYTE:
            return buf
        case rfctype if rfctype == RFCTYPE_STRING:
            # UTF-8 ending in one NUL byte, the empty string being just the NUL. Live
            # 2026-11-12: "Hello" travels as 48 65 6c 6c 6f 00, in both directions
            # (tests/golden/serialization/string_xstring.json). Drop the terminator.
            raw = bytes(buf)
            return (raw[:-1] if raw.endswith(b"\x00") else raw).decode("utf-8")
        case rfctype if rfctype == RFCTYPE_XSTRING:
            return buf
        case rfctype if rfctype == RFCTYPE_STRUCTURE:
            return _decode_structure(buf, _require_type_desc(field, "decode"), field.unicode_mode)
        case rfctype if rfctype == RFCTYPE_TABLE:
            return _decode_table(buf, field, row_count)
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
        case rfctype if rfctype == RFCTYPE_UTCLONG:
            return _encode_utclong(value)
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
            # UTF-8 plus the terminating NUL the reference client sends (see decode).
            return cast(bytes, value.encode("utf-8")) + b"\x00"
        case rfctype if rfctype == RFCTYPE_XSTRING:
            return bytes(value)
        case rfctype if rfctype == RFCTYPE_STRUCTURE:
            return _encode_structure(value, _require_type_desc(field, "encode"), field.unicode_mode)
        case rfctype if rfctype == RFCTYPE_TABLE:
            return _encode_table(value, field)
        case _:
            raise ValueError(f"unknown RFCTYPE {rfctype}")
