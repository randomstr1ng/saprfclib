# ABAP Type Serialization Wire Encoding

## Overview

RFC serializes function parameters using a type system identified by numeric type codes — the
`RFCTYPE` values used throughout this page. Each scalar field is serialized according to its
type into a contiguous byte sequence inside the RFC message payload, driven by the field's
type, length, and decimal precision from its descriptor.

Fixed-size types occupy a static byte count. Variable-length types (`RFCTYPE_STRING`,
`RFCTYPE_XSTRING`) carry **no internal length prefix** — the enclosing TLV header (tag `0x0203`)
carries the byte count. `RFCTYPE_STRING` content is UTF-8 (SAP codepage 4110); `RFCTYPE_XSTRING`
is raw bytes.

Fixed-width CHAR/DATE/TIME/NUM use SAP's wide-character encoding (UTF-16); the byte order is
settled by the codepage negotiated during the logon handshake — see [handshake.md](handshake.md).
Every system tested negotiates `4103`, which is UTF-16LE. IEEE 754r decimal floats
(DecFloat16/34) are transmitted big-endian regardless of machine byte order.

!!! note "Status: Live Capture Confirmed 2026-06-26"
    INT4, INT2, INT1, FLOAT, CHAR, DATE, and TIME byte encodings are now **CONFIRMED** from
    live capture of `STFC_STRUCTURE` (SAP NetWeaver 7.58, sysnr=00, 2026-06-26). Fixtures under
    `tests/golden/serialization/` are real wire bytes. BCD is confirmed from a live capture of a
    positive P15.2 value; the negative sign nibble and DecFloat16/34 remain unconfirmed on the
    wire. See [Known Gaps](#known-gaps).

---

## RFCTYPE Enum Values

The 25 concrete type codes `saprfclib` handles. Values 31–40 (`RFCTYPE_INT8` through
`RFCTYPE_CDAY`) continue the sequence from `RFCTYPE_XSTRING = 30`; the dispatch values and their
little-endian byte order were confirmed 2026-07-05.

| Value | Name | Wire Size | ABAP Type | Description |
|-------|------|-----------|-----------|-------------|
| 0 | `RFCTYPE_CHAR` | N × 2 bytes (UTF-16) | C | Fixed-length char, blank-padded in UC mode |
| 1 | `RFCTYPE_DATE` | 16 bytes (8 UC chars) | D | Date: YYYYMMDD in UTF-16 |
| 2 | `RFCTYPE_BCD` | 1–16 bytes | P | Packed BCD decimal; length from descriptor |
| 3 | `RFCTYPE_TIME` | 12 bytes (6 UC chars) | T | Time: HHMMSS in UTF-16 |
| 4 | `RFCTYPE_BYTE` | N bytes | X | Raw binary, fixed length, zero-padded |
| 5 | `RFCTYPE_TABLE` | — | — | Internal table (container, not scalar) |
| 6 | `RFCTYPE_NUM` | N × 2 bytes (UTF-16) | N | Numeric string, leading-zero-padded, UTF-16 |
| 7 | `RFCTYPE_FLOAT` | 8 bytes | F | IEEE 754 double-precision float |
| 8 | `RFCTYPE_INT` | 4 bytes | I | Signed 32-bit integer, little-endian |
| 9 | `RFCTYPE_INT2` | 2 bytes | — | Signed 16-bit integer (obsolete) |
| 10 | `RFCTYPE_INT1` | 1 byte | — | Unsigned 8-bit integer (obsolete) |
| 14 | `RFCTYPE_NULL` | — | — | Not supported — skip on wire |
| 16 | `RFCTYPE_ABAPOBJECT` | — | — | ABAP object handle — skip on wire |
| 17 | `RFCTYPE_STRUCTURE` | — | — | Nested structure, descriptor-driven |
| 23 | `RFCTYPE_DECF16` | 8 bytes | DECFLOAT16 | IEEE 754r DPD decimal float, big-endian wire |
| 24 | `RFCTYPE_DECF34` | 16 bytes | DECFLOAT34 | IEEE 754r DPD decimal float, big-endian wire |
| 28 | `RFCTYPE_XMLDATA` | — | — | No longer used — skip |
| 29 | `RFCTYPE_STRING` | variable | STRING | Null-terminated; length-prefixed on wire |
| 30 | `RFCTYPE_XSTRING` | variable | XSTRING | Raw bytes; length-prefixed (byte count) |
| 31 [A1] | `RFCTYPE_INT8` | 8 bytes | INT8 | Signed 64-bit integer |
| 32 [A1] | `RFCTYPE_UTCLONG` | 8 bytes | UTCLONG | UTC timestamp/long (8-byte integer) |
| 33 [A1] | `RFCTYPE_UTCSECOND` | 8 bytes | UTCSECOND | UTC timestamp/second (8-byte integer) |
| 34 [A1] | `RFCTYPE_UTCMINUTE` | 8 bytes | UTCMINUTE | UTC timestamp/minute (8-byte integer) |
| 35 [A1] | `RFCTYPE_DTDAY` | 4 bytes | DTDAY | Date/day (4-byte integer) |
| 36 [A1] | `RFCTYPE_DTWEEK` | 4 bytes | DTWEEK | Date/week (4-byte integer) |
| 37 [A1] | `RFCTYPE_DTMONTH` | 4 bytes | DTMONTH | Date/month (4-byte integer) |
| 38 [A1] | `RFCTYPE_TSECOND` | 4 bytes | TSECOND | Time/second (4-byte integer) |
| 39 [A1] | `RFCTYPE_TMINUTE` | 2 bytes | TMINUTE | Time/minute (2-byte integer) |
| 40 [A1] | `RFCTYPE_CDAY` | 2 bytes | CDAY | Calendar day (2-byte integer) |
| — | `RFCTYPE_BOX` | — | — | Out of scope (SDK: not supported) |
| — | `RFCTYPE_GENERIC_BOX` | — | — | Out of scope (SDK: not supported) |

**[A1]** Values 31–40 continue the sequence from `RFCTYPE_XSTRING = 30`. Dispatch values and
byte widths confirmed 2026-07-05.

---

## Byte Layout

### RFCTYPE_CHAR (type=0) — Fixed-length UTF-16 Character String

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | N×2 | UTF-16-LE | `char_data` | `41 00 42 00` ("AB") | N = CHAR length from descriptor; blank-padded with U+0020 (0x20 0x00) |

**Wire size:** `field_length × 2` bytes (each character is 2 bytes in UTF-16).

**PITFALL:** `field_length` is in *characters*, not bytes. Wire size is 2× the descriptor length. This is a classic off-by-2x error.

**Python encode/decode:**
```python
# Decode: 4 bytes → 2 chars
value = wire_bytes.decode('utf-16-le')
# Encode: 2 chars → 4 bytes (right-pad with spaces if needed)
wire_bytes = value.ljust(field_length).encode('utf-16-le')
```

**Hex Example (constructed, not captured):**
```hex
41 00 42 00  -- "AB" as UTF-16-LE (CHAR(2))
```

---

### RFCTYPE_DATE (type=1) — Date Field (16 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 16 | UTF-16-LE | `date_string` | `32 00 30 00 32 00 36 00 30 00 36 00 32 00 36 00` | Fixed 8 UC chars = "YYYYMMDD" |

**Wire size:** Always 16 bytes (8 CHAR, each 2 bytes).

**Python decode:**
```python
value = wire_bytes.decode('utf-16-le')  # → "20260626"
```

**Hex Example (constructed, not captured):**
```hex
32 00 30 00 32 00 36 00 30 00 36 00 32 00 36 00  -- "20260626"
```

---

### RFCTYPE_BCD (type=2) — Packed BCD Decimal

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | `ceil((decimals+1)/2)` | packed-BCD | `bcd_digits` | `01 23` | Digit pairs in each byte, high nibble = MSD |
| last | 1 (last nibble) | nibble | `sign_nibble` | `0x4C` (low nibble of last byte) | 0x0C or 0x0F = positive; 0x0D = negative; 0x0B = positive (alt) |

**Wire size:** `ceil((precision + 1) / 2)` bytes, where `precision` is the total digit count.

**Packing rules** (BCD is an array of raw bytes; the digits are packed two per byte):
- Each byte holds two decimal digits: high nibble = more significant digit, low nibble = less significant digit.
- The final *nibble* of the last byte is the sign: `0x0C` or `0x0F` = positive, `0x0D` = negative, `0x0B` = positive alternative.
- **Odd digit count:** last byte has one digit in the high nibble + sign in the low nibble.
- **Even digit count:** last byte has two digits; the sign nibble is appended as the low nibble of one extra byte.
- **Zero / initial form:** all bytes `0x00` with sign nibble `0x0C` in the trailing nibble.

**Sign nibble summary:**
| Nibble | Meaning |
|--------|---------|
| `0x0C` | Positive (canonical) |
| `0x0F` | Positive (alternate, e.g. from BCD hardware) |
| `0x0D` | Negative |
| `0x0B` | Positive (alternate, rarely used) |

**Evidence:** the positive sign nibble `0x0C` is confirmed from a live capture (see below). The
alternate positive nibbles (`0x0F`, `0x0B`) and the negative nibble (`0x0D`) come from documented
SDK type behaviour and are **[ASSUMED]** on the wire — no live negative value has been captured,
because the reachable test data (SFLIGHT prices) is all positive.

**Python encode (example for 123.45 as BCD(5,2)):**
```python
import math

def encode_bcd(value: str, precision: int) -> bytes:
    """Encode a decimal string to packed BCD.
    value: digits only string (e.g. '12345' for 123.45)
    precision: total digit count
    """
    negative = value.startswith('-')
    digits = value.lstrip('-').replace('.', '').zfill(precision)
    sign = 0x0D if negative else 0x0C
    n_bytes = math.ceil((precision + 1) / 2)
    result = bytearray(n_bytes)
    # Pack digits from right (least significant)
    j = len(digits) - 1
    for i in range(n_bytes - 1, -1, -1):
        low = sign if i == n_bytes - 1 else (int(digits[j]) if j >= 0 else 0)
        j -= (1 if i == n_bytes - 1 else 1)
        high = int(digits[j]) if j >= 0 else 0
        j -= 1
        result[i] = (high << 4) | low
    return bytes(result)
```

**Hex Example (constructed, not captured; BCD(5,2)):**
```hex
01 23 4C  -- BCD(5,2): digits=01234, sign=0x0C (positive) → 12.34
           -- Byte 0: 0x01 = high nibble 0 (leading zero), low nibble 1
           -- Byte 1: 0x23 = high nibble 2, low nibble 3
           -- Byte 2: 0x4C = high nibble 4 (digit), low nibble C (sign=positive)
```
> NOTE: these synthetic bytes `01 23 4C` decode (digits `01234`, decimals=2) to
> **12.34**, not 123.45. The earlier "123.45" annotation was an inconsistency in the
> synthetic fixture text; the *authoritative* BCD example is the live `type_bcd_p15_2`
> capture below. `123.45` at BCD(5,2) is `12 34 5C` (digits `12345`), which the codec's
> Hypothesis round-trips also cover. The `type_bcd` fixture still replays byte-for-byte
> because decode→encode is value-faithful to whatever bytes it is handed.

**Hex Example (live capture — BAPISFLIGHT.PRICE = 800000.50 as P15.2, SAP A4H 2026-06-26) [live]:**
```hex
00 00 00 08 00 00 05 0C  -- BCD(15,2): digits=000000080000050, sign=0x0C (positive) → 800000.50
                          -- 8 bytes = ceil((15+1)/2); digit pairs MSD→LSD, last nibble = sign
                          -- Source: BAPI_FLIGHT_GETLIST FLIGHT_LIST.PRICE; port 3300 offset 0x44D
```
This live capture confirms the packed-BCD scheme (2 digits/byte, sign in
the low nibble of the last byte, 0x0C=positive) on real SAP wire bytes. The negative sign nibble
(0x0D) remains unconfirmed on the wire — SFLIGHT prices are positive, so no live negative value
was reachable. Fixture: `tests/golden/serialization/type_bcd_p15_2.{bin,json}`.

**Codec status — IMPLEMENTED:** `_decode_bcd` / `_encode_bcd` in `src/saprfclib/codec.py`
implement the scheme above using `decimal.Decimal` exclusively — never `float`, which cannot
represent base-10 decimals exactly and would corrupt financial values. The total digit count is
derived from the descriptor's wire byte width (`width * 2 - 1`); decode accepts `0x0C`/`0x0F`/`0x0B`
as positive and `0x0D` as negative, while encode emits only canonical `0x0C`/`0x0D`. A malformed
buffer (too short) or a non-digit nibble in a digit position raises a typed `ValueError`
(threats T-02-09 / T-02-11). Both BCD fixtures (`type_bcd`, `type_bcd_p15_2`) replay byte-for-byte;
Hypothesis round-trips cover sign nibbles, odd/even lengths, the zero/initial form, and max decimals.

---

### RFCTYPE_TIME (type=3) — Time Field (12 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 12 | UTF-16-LE | `time_string` | `31 00 34 00 33 00 30 00 30 00 30 00` | Fixed 6 UC chars = "HHMMSS" |

**Wire size:** Always 12 bytes (6 CHAR, each 2 bytes).

**Hex Example (live capture — "120000", SAP A4H 2026-06-26):**
```hex
31 00 32 00 30 00 30 00 30 00 30 00  -- "120000" (12:00:00)
                                     -- STFC_STRUCTURE IMPORTSTRUCT offset 36
```

---

### RFCTYPE_BYTE (type=4) — Raw Binary

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | N | bytes | `byte_data` | `DE AD BE EF` | Fixed length N from descriptor; zero-padded if shorter |

**Wire size:** `field_length` bytes exactly (no UTF-16 factor — this is raw binary).

---

### RFCTYPE_NUM (type=6) — Numeric String (UTF-16, zero-padded)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | N×2 | UTF-16-LE | `num_string` | `30 00 30 00 34 00 32 00` | Leading-zero-padded to width N, UTF-16-LE |

**Wire size:** `field_length × 2` bytes (same UTF-16 encoding as CHAR, different padding).

**Hex Example (synthetic — 42 as NUM(4)):**
```hex
30 00 30 00 34 00 32 00  -- "0042" (leading-zero-padded)
```

---

### RFCTYPE_FLOAT (type=7) — IEEE 754 Double (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | IEEE 754 double | `float_value` | `6e 86 1b f0 f9 21 09 40` | **Confirmed** little-endian via live capture 2026-06-26 |

**Wire size:** Always 8 bytes.

**Confirmed from live capture 2026-06-26:** RFCFLOAT=3.14159 was serialized as `6e 86 1b f0 f9 21 09 40` — IEEE 754 double little-endian. Same byte order as machine-native x86-64.

**Python encode/decode:**
```python
import struct
value = struct.unpack('<d', wire_bytes)[0]  # little-endian double
wire_bytes = struct.pack('<d', value)
```

**Hex Example (live capture — 3.14159 as FLOAT):**
```hex
6e 86 1b f0 f9 21 09 40  -- 3.14159 as IEEE 754 double, little-endian
                          -- STFC_STRUCTURE IMPORTSTRUCT offset 0, SAP A4H 2026-06-26
```

---

### RFCTYPE_INT (type=8) — Signed 32-bit Integer (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `int_value` | `00 00 01 00` | Signed, **confirmed** little-endian (live capture 2026-06-26) |

**Wire size:** Always 4 bytes.

**Confirmed from live capture 2026-06-26:** RFCINT4=65536 was serialized as `00 00 01 00` — 4-byte little-endian signed integer. IMPORTSTRUCT offset 24 in STFC_STRUCTURE frame.

**Independently confirmed by arithmetic (STFC_CHANGING golden pair).** The request
carries `START_VALUE`=`0a000000` and `COUNTER`=`01000000`; the response carries
`RESULT`=`0b000000` and `COUNTER`=`02000000`. STFC_CHANGING returns
`RESULT = START_VALUE + COUNTER` and increments `COUNTER`, so read little-endian the
exchange is 10 + 1 = 11 and 1 → 2 — exactly the documented behaviour. Read big-endian
the inputs would be 167772160 and 16777216 and no reading of the response fits, so the
server demonstrably decoded the bytes as little-endian. This covers *parameter* INT4
values on the wire, not just an integer embedded in a structure.
Fixtures: `tests/golden/framing/stfc_changing_request.bin`, `stfc_changing_response.bin`.

**Python encode/decode:**
```python
import struct
value = struct.unpack('<i', wire_bytes)[0]   # little-endian signed int
wire_bytes = struct.pack('<i', value)
```

**Hex Example (live capture — 65536 as INT4):**
```hex
00 00 01 00  -- 65536 as signed 32-bit little-endian integer
             -- STFC_STRUCTURE IMPORTSTRUCT offset 24, SAP A4H 2026-06-26
```

---

### RFCTYPE_INT2 (type=9) — Signed 16-bit Integer (2 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 2 | int16-LE | `int2_value` | `2A 00` | Signed, little-endian; obsolete in ABAP/4 |

**Wire size:** Always 2 bytes. **Confirmed little-endian from live capture 2026-06-26:** RFCINT2=256 was serialized as `00 01` at IMPORTSTRUCT offset 10.

---

### RFCTYPE_INT1 (type=10) — Unsigned 8-bit Integer (1 byte)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 1 | uint8 | `int1_value` | `2A` | Unsigned; obsolete in ABAP/4 |

**Wire size:** Always 1 byte. No byte-order issue.

---

### RFCTYPE_NULL (type=14) — Unsupported

Not serialized. The SAP NW RFC SDK header documents this as "not supported data type." Skip in any type-switch implementation.

---

### RFCTYPE_ABAPOBJECT (type=16) — ABAP Object Handle

Not serialized over RFC wire. Internal ABAP object references cannot be passed between RFC clients and servers. Skip.

---

### RFCTYPE_STRUCTURE (type=17) — Nested Structure

Structure serialization is descriptor-driven. Each field within the structure is serialized according to its own RFCTYPE entry in the RFC_FIELD_DESC array. The byte layout depends on whether Unicode mode is active (determines `ucOffset` vs `nucOffset` field positioning).

**[ASSUMED]** Whether the Unicode or non-Unicode offset set applies is decided by the codepage
negotiated in the handshake. Every system tested negotiates Unicode mode, so only that path is
exercised; the non-Unicode layout is undocumented here.

---

### RFCTYPE_DECF16 (type=23) — IEEE 754r Decimal Float 16 (8 bytes)

!!! note "Metadata: DECFLOAT16 arrives with EXID `a` — CONFIRMED"
    `RFC_GET_FUNCTION_INTERFACE` reports a DECFLOAT16 parameter with `EXID = 'a'`,
    and DECFLOAT34 with `EXID = 'e'`. Confirmed by live capture on 2026-08-31: a
    remote-enabled function module on A4H (kernel 793) carrying seven DECFLOAT16
    and three DECFLOAT34 parameters reported `a` for all seven and `e` for all three.

    `_EXID_TO_RFCTYPE` previously mapped only `v` to DECFLOAT16, which has never
    been observed. Every DECFLOAT16 parameter therefore failed to parse and was
    dropped from the descriptor, so the interface silently lost them and the call
    went out short of those arguments. `a` is now mapped; `v` is retained and
    labelled `[ASSUMED]`.

    Note this is about the *metadata* only. The wire encoding of the value itself
    remains unconfirmed and `encode`/`decode` still raise — the failure simply moves
    from "parameters silently missing" to "this type is not implemented", which is
    the right shape for an unverified format.

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | DPD-BE | `decf16_wire` | big-endian bytes | IEEE 754r DPD, transmitted big-endian (neutral network form) |

**Wire size:** Always 8 bytes.

**Encoding:** IEEE 754r **Densely Packed Decimal (DPD)** in **Big-Endian (network) byte order**.

**Evidence tier: documented SDK type behaviour, not a capture.** The neutral network byte order
for DecFloat values is big-endian, and clients convert from machine-native order before writing.
This is HIGH confidence for the *byte order* but says nothing about how the value sits inside the
enclosing TLV record — which is the part no capture has confirmed.

**Python decode:**
```python
import struct
# Read 8 big-endian bytes from wire
raw_be = wire_bytes  # 8 bytes, big-endian DPD
# Convert BE bytes to integer for DPD decoding
raw_int = int.from_bytes(raw_be, 'big')
# DPD decoding is not in the stdlib — it needs an in-tree DPD↔BCD codec
```

**Hex Example (constructed, NOT captured — do not rely on these bytes):**
```hex
22 34 00 00 00 00 02 20  -- 42.0 encoded as IEEE 754-2008 decimal64, DPD, big-endian
                         -- arithmetic from the public IEEE standard, NOT a capture.
                         -- Whether SAP puts DPD on the wire at all is still [ASSUMED].
```

The previous version of this example read `22 38 00 00 00 00 04 20`. Those bytes do
not encode 42.0 — under a standard DPD reading they are `1020`. Two separate errors:
the exponent field said 0 rather than −1 (`38` vs `34`), and the declet `0x420` spells
the digits 2‑2‑0 rather than 4‑2‑0, which is `0x220`. Nothing depended on it, because
the codec raises rather than encoding, but a wrong worked example is a trap for whoever
implements this — it looks like something to check an implementation against.

**Telling DPD from BID from one captured value.** The two schemes differ visibly at
small integers, which makes a single capture decisive rather than suggestive: the
number **twelve** is `…00 12` under DPD (each declet spells three decimal digits) and
`…00 0c` under BID (the coefficient is a plain binary integer). Any captured DECFLOAT
whose value is known settles the question immediately; no inference required.

!!! warning "DecFloat16/34 is unconfirmed on the wire — and therefore unimplemented"
    A live probe on 2026-06-26 found no reachable function module exposing a DECFLOAT16/34
    parameter — `STFC_DECFLOAT`, `RFC_DECFLOAT_TEST` and `DEMO_DECFLOAT_ARITH` all returned
    `FU_NOT_FOUND`. Big-endian DPD is HIGH confidence from documented type behaviour, but nothing
    has been seen on the wire.

    Note what that probe actually established: three guessed function-module names do not
    exist. That is not the same as "no such function module exists", and it should not be
    read as one. The dictionary can be asked directly — `DD04L`/`DD03L` for DECFLOAT-typed
    data elements and structure fields, `FUPARAREF` for the parameters referencing them, and
    `TFDIR` (`FMODE = 'R'`) for the remote-enabled subset — which turns "we did not find one"
    into an evidenced answer either way.

    Rather than ship a plausible guess that could silently corrupt decimal values, `encode` and
    `decode` in `src/saprfclib/codec.py` **raise `NotImplementedError`** for `RFCTYPE_DECF16` (23)
    and `RFCTYPE_DECF34` (24). A loud failure is correct here; a wrong decimal is not.

    This stays until a live DecFloat capture lands. Marker fixture:
    `tests/golden/serialization/type_decf16_GAP.json`.

---

### RFCTYPE_DECF34 (type=24) — IEEE 754r Decimal Float 34 (16 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 16 | DPD-BE | `decf34_wire` | big-endian bytes | IEEE 754r DPD, transmitted big-endian (neutral network form) |

**Wire size:** Always 16 bytes.

**Encoding:** the same big-endian DPD scheme as DECF16, converted from machine-native order
before the write.

**Same gap as DECF16** — unconfirmed on the wire, and `NotImplementedError` rather than a guess.

---

### RFCTYPE_XMLDATA (type=28) — Obsolete

No longer used. Skip; do not implement.

---

### RFCTYPE_STRING (type=29) — Variable-Length String

**Wire:** UTF-8 encoded content, **no internal length prefix**. The length is carried by the
enclosing TLV header (tag `0x0203`) as a byte count. Confirmed 2026-07-05 — an earlier assumption
of a leading little-endian uint32 length plus UTF-16LE content was **wrong**, and the codec was
corrected.

| TLV header | TLV payload |
|------------|-------------|
| `[0x02 0x03][utf8_byte_count]` | `[utf8_bytes]` |

**Python decode:**
```python
string_value = tlv_payload.decode("utf-8")
```

**Hex Example ("ABC" as STRING, TLV payload only):**
```hex
41 42 43  -- "ABC" in UTF-8
```

---

### RFCTYPE_XSTRING (type=30) — Variable-Length Raw Bytes

**Wire:** raw bytes, **no internal length prefix**. The length is carried by the enclosing TLV
header (tag `0x0203`) as a byte count. Same pattern as STRING (confirmed 2026-07-05).

| TLV header | TLV payload |
|------------|-------------|
| `[0x02 0x03][raw_byte_count]` | `[raw_bytes]` |

**Python decode:**
```python
xstring_value = tlv_payload  # bytes as-is
```

---

### RFCTYPE_INT8 (type=31) — Signed 64-bit Integer (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | int64-LE | `int8_value` | `2A 00 00 00 00 00 00 00` | Signed, little-endian |

**Wire size:** always 8 bytes, little-endian — the same write path as FLOAT (confirmed 2026-07-05).

---

### RFCTYPE_UTCLONG (type=32) — UTC Timestamp Long (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | int64-LE | `utclong_value` | — | Signed 8-byte integer |

Same write path as INT8 — little-endian, 8 bytes (confirmed 2026-07-05).

---

### RFCTYPE_UTCSECOND (type=33) — UTC Timestamp Second (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | int64-LE | `utcsecond_value` | — | Signed 8-byte integer **(confirmed 2026-07-05)** |

---

### RFCTYPE_UTCMINUTE (type=34) — UTC Timestamp Minute (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | int64-LE | `utcminute_value` | — | Signed 8-byte integer **(confirmed 2026-07-05)** |

---

### RFCTYPE_DTDAY (type=35) — Date Day (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `dtday_value` | — | 4-byte integer **(confirmed 2026-07-05)** |

---

### RFCTYPE_DTWEEK (type=36) — Date Week (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `dtweek_value` | — | 4-byte integer **(confirmed 2026-07-05)** |

---

### RFCTYPE_DTMONTH (type=37) — Date Month (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `dtmonth_value` | — | 4-byte integer **(confirmed 2026-07-05)** |

---

### RFCTYPE_TSECOND (type=38) — Time Second (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `tsecond_value` | — | 4-byte integer **(confirmed 2026-07-05)** |

---

### RFCTYPE_TMINUTE (type=39) — Time Minute (2 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 2 | int16-LE | `tminute_value` | — | 2-byte integer **(confirmed 2026-07-05)** |

---

### RFCTYPE_CDAY (type=40) — Calendar Day (2 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 2 | int16-LE | `cday_value` | — | 2-byte integer **(confirmed 2026-07-05)** |

---

## Hex Examples

Examples marked **[live]** are from live STFC_STRUCTURE capture, SAP A4H, 2026-06-26.
Examples marked **[synthetic]** are constructed; wire byte order confirmed but value/context is illustrative.

### INT4 (65536 as RFCTYPE_INT) **[live]**
```hex
00 00 01 00  -- 65536 as signed 32-bit little-endian integer
             -- IMPORTSTRUCT offset 24, RFCINT4 field
```

### INT2 (256 as RFCTYPE_INT2) **[live]**
```hex
00 01  -- 256 as signed 16-bit little-endian integer
       -- IMPORTSTRUCT offset 10, RFCINT2 field
```

### FLOAT (3.14159 as RFCTYPE_FLOAT) **[live]**
```hex
6e 86 1b f0 f9 21 09 40  -- 3.14159 as IEEE 754 double, little-endian
                          -- IMPORTSTRUCT offset 0, RFCFLOAT field
```

### CHAR (RFCTYPE_CHAR, CHAR(1) = "A") **[live]**
```hex
41 00  -- "A" as UTF-16-LE (1 char × 2 bytes)
       -- IMPORTSTRUCT offset 8, RFCCHAR1 field
```

### CHAR (RFCTYPE_CHAR, CHAR(4) = "ABCD") **[live]**
```hex
41 00 42 00 43 00 44 00  -- "ABCD" as UTF-16-LE (4 chars × 2 bytes = 8 bytes)
                         -- IMPORTSTRUCT offset 14, RFCCHAR4 field
```

### DATE (RFCTYPE_DATE = "20260626") **[live]**
```hex
32 00 30 00 32 00 36 00 30 00 36 00 32 00 36 00
-- "20260626" as UTF-16-LE (8 chars × 2 bytes = 16 bytes)
-- IMPORTSTRUCT offset 48, RFCDATE field
```

### TIME (RFCTYPE_TIME = "120000") **[live]**
```hex
31 00 32 00 30 00 30 00 30 00 30 00  -- "120000" as UTF-16-LE (6 chars × 2 bytes = 12 bytes)
                                     -- IMPORTSTRUCT offset 36, RFCTIME field
```

### BCD (RFCTYPE_BCD, BCD(5,2) = 123.45) **[synthetic]**
```hex
01 23 4C  -- Packed BCD: 01=0x0,0x1; 23=0x2,0x3; 4C=0x4, sign=0xC(+)
           -- Represents digits 01234 with sign=positive, decimals=2 → 123.45
```

### STRING (RFCTYPE_STRING = "Hello")
```hex
48 65 6C 6C 6F  -- "Hello" in UTF-8 (SAP codepage 4110); TLV header carries byte count
```

---

## Evidence Summary

| Type group | Status | Evidence |
|------------|--------|----------|
| INT, INT2, INT1, FLOAT | **CONFIRMED** | Live capture 2026-06-26 — little-endian confirmed for all four |
| CHAR, DATE, TIME | **CONFIRMED** | Live capture 2026-06-26 — UTF-16LE, fixed width |
| NUM, BYTE | **CONFIRMED** | Live capture — UTF-16LE zero-padded / raw fixed-length bytes |
| STRING, XSTRING | **CONFIRMED** | Confirmed 2026-07-05 — no internal length prefix; TLV header carries the byte count |
| INT8, UTCLONG…CDAY (31–40) | **CONFIRMED** | Dispatch values and little-endian widths confirmed 2026-07-05 |
| BCD | **PARTIAL** | Positive sign nibble live-captured; negative nibble unconfirmed |
| STRUCTURE | **PARTIAL** | Unicode offset layout exercised; non-Unicode layout undocumented |
| DECF16, DECF34 | **UNCONFIRMED** | Big-endian DPD is documented behaviour; nothing seen on the wire. Not implemented. |

---

## Known Gaps

### DecFloat16 / DecFloat34 wire form — OPEN

No reachable function module on the test system exposes a DECFLOAT-typed parameter
(`STFC_DECFLOAT`, `RFC_DECFLOAT_TEST`, `DEMO_DECFLOAT_ARITH` all returned `FU_NOT_FOUND`,
probed 2026-06-26). Big-endian DPD is HIGH-confidence documented behaviour but has never been
observed on the wire, and no fixture is fabricated to paper over that.

`encode` and `decode` raise `NotImplementedError` for both types. **Consequence:** a function
module with a DECFLOAT parameter cannot be called until a capture lands. This is deliberate —
a guessed decimal codec that is subtly wrong corrupts financial data silently, which is worse
than a clear failure.

**To close:** capture a live DECFLOAT16 and DECFLOAT34 value and commit both as fixtures.

### BCD negative sign nibble — OPEN

The positive nibble `0x0C` is live-captured (`BAPI_FLIGHT_GETLIST` → `FLIGHT_LIST.PRICE`,
P15.2, wire bytes `00 00 00 08 00 00 05 0C` = 800000.50). The negative nibble `0x0D` and the
alternate positive nibbles `0x0F` / `0x0B` are documented but unconfirmed on the wire, because
the reachable test data (SFLIGHT prices) contains no negative value.

`saprfclib` encodes and decodes all four nibbles per the documented convention. **Consequence:**
if the convention is wrong for negatives, a negative packed decimal would decode with the wrong
sign. **To close:** capture a function module returning a negative packed decimal.

### STRUCTURE non-Unicode offsets — OPEN

Structure field positioning uses one of two offset sets depending on whether the session
negotiated Unicode mode. Every system tested negotiates `4103` (UTF-16LE), so only the Unicode
layout is exercised or documented. **Consequence:** none for any currently reachable system.

---

## Open Questions

| # | Question | Status |
|---|----------|--------|
| OQ-01 | RFCTYPE_INT byte order on the wire | **RESOLVED** — little-endian, live capture 2026-06-26 |
| OQ-02 | RFCTYPE_FLOAT byte order | **RESOLVED** — little-endian IEEE 754 double, live capture |
| OQ-03 | STRING/XSTRING length prefix — LE or BE uint32? | **RESOLVED 2026-07-05** — there is no internal prefix. STRING is UTF-8 in the TLV, XSTRING is raw bytes, and the TLV header carries the byte count. The earlier assumption (LE uint32 + UTF-16LE) was wrong and the codec was corrected. |
| OQ-04 | BCD odd digit count — digit+sign in the last byte, or padding? | **RESOLVED** — live P15.2 capture confirms final digit in the high nibble, sign in the low nibble, no padding |
| OQ-05 | STRUCTURE field layout — which offset set, and how is it selected? | **OPEN** — decided by the negotiated codepage; only the Unicode path is exercised |
| OQ-06 | Are temporal types (UTCLONG…CDAY) serialized like INT8? | **RESOLVED 2026-07-05** — UTCLONG/UTCSECOND/UTCMINUTE are 8-byte LE; DTDAY/DTWEEK/DTMONTH/TSECOND are 4-byte LE; TMINUTE/CDAY are 2-byte LE. All use the same write path as INT8/INT4/INT2. |

---

*See also: [Framing](framing.md), [Handshake](handshake.md), [Methodology](methodology.md).*
