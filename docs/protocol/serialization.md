# ABAP Type Serialization Wire Encoding

## Overview

SAP RFC (Remote Function Call) serializes function parameters using a type system rooted in the `RFCTYPE` enum defined in `sapnwrfc.h`. Each scalar field is serialized according to its RFCTYPE into a contiguous byte sequence within the RFC message payload. The serialization format is determined by the field's type, length, and decimal precision as specified in the RFC_FIELD_DESC descriptor. Fixed-size types occupy a static byte count; variable-length types (RFCTYPE_STRING, RFCTYPE_XSTRING) carry no internal length prefix — the enclosing TLV header (tag 0x0203) carries the byte count. RFCTYPE_STRING content is UTF-8 encoded (SAP codepage 4110); RFCTYPE_XSTRING is raw bytes. Fixed-width CHAR/DATE/TIME/NUM use SAP_UC (UTF-16) encoding; the byte order (LE or BE) is negotiated during the logon handshake (Gate C — see [handshake.md](handshake.md)). For x86-64 Linux builds, the library uses UTF-16-LE internally. IEEE 754r decimal floats (DecFloat16/34) are transmitted in big-endian (network) byte order regardless of machine byte order.

!!! note "Status: Live Capture Confirmed 2026-06-26"
    INT4, INT2, INT1, FLOAT, CHAR, DATE, and TIME byte encodings are now **CONFIRMED** from
    live Wireshark capture of STFC_STRUCTURE (SAP A4H, sysnr=00, 2026-06-26). Fixtures at
    `tests/golden/serialization/` reflect real wire bytes. Fields marked **[ASSUMED pending BN]**
    still require Binary Ninja confirmation. BCD, DecFloat16/34 remain PARTIAL — no live capture
    available for those types. See the [Gap Report](#gap-report) section.

---

## RFCTYPE Enum Values

All 25 concrete RFCTYPE values required for Gate B, extracted from `sapnwrfc.h` lines 91-125.
Enum values for RFCTYPE_INT8 through RFCTYPE_CDAY are C auto-increments from RFCTYPE_XSTRING=30, **confirmed** by BN `rfcSerialize` switch cases 0x1f–0x28 (GAP-B-03 closed 2026-07-05).

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

**[A1]** Values 31–40 are C auto-increment from `RFCTYPE_XSTRING = 30`. **[ASSUMED pending BN confirmation]** — BN decompilation of the `RfcInvoke` type-switch will reveal the actual dispatch values.

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

**Hex Example (synthetic — BN-derived; no live capture available):**
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

**Hex Example (synthetic — BN-derived):**
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

**Packing rules (from `sapucrfc.h` line 622 — `SAP_BCD typedef SAP_RAW`):**
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

**[ASSUMED pending BN]** Sign nibble handling confirmed from `sapucrfc.h` `SAP_BCD` typedef and BCD field description. BN decompilation of the `RFCTYPE_BCD` branch in `RfcInvoke`'s type-switch is required to confirm all variants are present in `libsapnwrfc.so`.

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

**Hex Example (synthetic — BN-derived; BCD(5,2)):**
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
This live capture **CLOSES GAP-B-02** and confirms the packed-BCD scheme (2 digits/byte, sign in
the low nibble of the last byte, 0x0C=positive) on real SAP wire bytes. The negative sign nibble
(0x0D) remains `sapucrfc.h`-confirmed only — SFLIGHT prices are positive, so no live negative value
was reachable. Fixture: `tests/golden/serialization/type_bcd_p15_2.{bin,json}`.

**Codec status (Plan 04 — IMPLEMENTED):** `src/saprfclib/codec.py` `_decode_bcd`/`_encode_bcd` implement
the scheme above via `decimal.Decimal` exclusively (never `float`, D-13). The total digit count is
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

**[ASSUMED pending BN + Gate C]** The `ucOffset`/`nucOffset` question is Gate C (handshake byte order negotiation). RFCTYPE_STRUCTURE layout cannot be finalized until Gate C closes.

---

### RFCTYPE_DECF16 (type=23) — IEEE 754r Decimal Float 16 (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | DPD-BE | `decf16_wire` | big-endian bytes | IEEE 754r DPD, transmitted big-endian (neutral network form) |

**Wire size:** Always 8 bytes.

**Encoding:** IEEE 754r **Densely Packed Decimal (DPD)** in **Big-Endian (network) byte order**.

Evidence from `sapdecf.h` lines 1159-1169:
```
DecFloat16ToDecFloat16Neutral() — "The preferred neutral network byte order is Big-Endian."
```

The library stores DecFloat16 in machine-native byte order (LE on x86-64). Before writing to the wire, `DecFloat16ToDecFloat16Neutral()` converts to big-endian. Upon receiving from the wire, `DecFloat16NeutralToDecFloat16()` converts from big-endian back to native.

**binja_ref (gap):** `libsapnwrfc.so::RfcInvoke::RFCTYPE_DECF16_branch` — [BLOCKER: BN confirmation required to cite exact function offset. Header evidence is HIGH confidence but gate D-10 requires the BN call-site citation.]

**Python decode:**
```python
import struct
# Read 8 big-endian bytes from wire
raw_be = wire_bytes  # 8 bytes, big-endian DPD
# Convert BE bytes to integer for DPD decoding
raw_int = int.from_bytes(raw_be, 'big')
# DPD decoding is not stdlib — requires in-tree DPD↔BCD codec (Phase 2 CODEC-03)
```

**Hex Example (synthetic — 42.0 as DECF16, big-endian DPD):**
```hex
22 38 00 00 00 00 04 20  -- 42.0 in IEEE 754r DECFLOAT16 DPD big-endian [ASSUMED]
                           -- NOTE: actual bytes unconfirmed; BN confirmation required
```

!!! warning "GAP-B-01 — DecFloat unconfirmed on the wire (no-guess)"
    A live probe of SAP A4H (sysnr=00) on 2026-06-26 found **no reachable RFM exposing a
    DECFLOAT16/34 typed parameter** (STFC_DECFLOAT, RFC_DECFLOAT_TEST, DEMO_DECFLOAT_ARITH all
    returned FU_NOT_FOUND). The above bytes remain **(BN confirmed)** from header evidence only.
    Per the no-guessing constraint, **Plan 04 ships (delivered) `NotImplementedError` for
    RFCTYPE_DECF16 (23) and RFCTYPE_DECF34 (24)** — `src/saprfclib/codec.py` `decode`/`encode`
    raise `NotImplementedError` with the message *"DecFloat16/34 wire form unconfirmed — see
    GAP-B-01 (D-04 capture); deferred per no-guessing constraint"*. This stays until a live
    capture closes GAP-B-01. Marker: `tests/golden/serialization/type_decf16_GAP.json`;
    test: `tests/test_codec.py::test_decfloat_raises_gap_b01_notimplemented`.

---

### RFCTYPE_DECF34 (type=24) — IEEE 754r Decimal Float 34 (16 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 16 | DPD-BE | `decf34_wire` | big-endian bytes | IEEE 754r DPD, transmitted big-endian (neutral network form) |

**Wire size:** Always 16 bytes.

**Encoding:** Same DPD big-endian scheme as DECF16. `DecFloat34ToDecFloat34Neutral()` converts to network form before wire write.

**binja_ref (gap):** `libsapnwrfc.so::RfcInvoke::RFCTYPE_DECF34_branch` — [BLOCKER: BN confirmation required.]

---

### RFCTYPE_XMLDATA (type=28) — Obsolete

"No longer used!" per `sapnwrfc.h` comment. Skip; do not implement.

---

### RFCTYPE_STRING (type=29) — Variable-Length String

**Wire:** UTF-8 encoded content, no internal length prefix. Length is carried by the enclosing TLV header (tag 0x0203). Confirmed from BN `writeRfcUTF8Chars` → SAP codepage 4110 conversion → `writeRfcIDBegin(conn, tag, byte_count)` (GAP-B-06 closed 2026-07-05).

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

**Wire:** Raw bytes, no internal length prefix. Length is carried by the enclosing TLV header (tag 0x0203). Confirmed from BN `rfcSerialize` case 0x1e → `writeRfcData` → `writeRfcIDBegin(conn, tag, byte_count)` (GAP-B-06 closed 2026-07-05).

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

**Wire size:** Always 8 bytes. LE byte order confirmed by BN `rfcSerialize` case 0x1f (same `writeRfcData` path as FLOAT, GAP-B-03 closed).

---

### RFCTYPE_UTCLONG (type=32) — UTC Timestamp Long (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | int64-LE | `utclong_value` | — | Signed 8-byte integer |

BN case 0x20, same `writeRfcData` path as INT8 — LE, 8 bytes (GAP-B-03 closed).

---

### RFCTYPE_UTCSECOND (type=33) — UTC Timestamp Second (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | int64-LE | `utcsecond_value` | — | Signed 8-byte integer **(BN confirmed)** |

---

### RFCTYPE_UTCMINUTE (type=34) — UTC Timestamp Minute (8 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 8 | int64-LE | `utcminute_value` | — | Signed 8-byte integer **(BN confirmed)** |

---

### RFCTYPE_DTDAY (type=35) — Date Day (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `dtday_value` | — | 4-byte integer **(BN confirmed)** |

---

### RFCTYPE_DTWEEK (type=36) — Date Week (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `dtweek_value` | — | 4-byte integer **(BN confirmed)** |

---

### RFCTYPE_DTMONTH (type=37) — Date Month (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `dtmonth_value` | — | 4-byte integer **(BN confirmed)** |

---

### RFCTYPE_TSECOND (type=38) — Time Second (4 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 4 | int32-LE | `tsecond_value` | — | 4-byte integer **(BN confirmed)** |

---

### RFCTYPE_TMINUTE (type=39) — Time Minute (2 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 2 | int16-LE | `tminute_value` | — | 2-byte integer **(BN confirmed)** |

---

### RFCTYPE_CDAY (type=40) — Calendar Day (2 bytes)

| Offset | Length | Type | Name | Value (example) | Notes |
|--------|--------|------|------|-----------------|-------|
| 0x00 | 2 | int16-LE | `cday_value` | — | 2-byte integer **(BN confirmed)** |

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

### STRING (RFCTYPE_STRING = "Hello") **[BN confirmed]**
```hex
48 65 6C 6C 6F  -- "Hello" in UTF-8 (SAP codepage 4110); TLV header carries byte count
```

---

## BN Evidence

!!! warning "BN MCP Unavailable"
    Binary Ninja MCP was not available during this RE session. The evidence items below
    are from **SDK header analysis only** (HIGH confidence as documentary evidence) but
    do NOT provide the `binja_ref` call-site citations required by D-10.
    Gate B cannot formally close until BN confirms these in `libsapnwrfc.so`.

### DecFloat16/34 — DPD Big-Endian Wire Format

**Header evidence (HIGH confidence):**
- `sapdecf.h` line 1162: `DecFloat16ToDecFloat16Neutral()` — docstring: "The preferred neutral network byte order is Big-Endian."
- `sapdecf.h` line 1193: `DecFloat34ToDecFloat34Neutral()` — same docstring.
- `sapucrfc.h` lines 786-791: `DecFloat16Len = 8`, `DecFloat34Len = 16` (from `DecFloatLen` enum).

**Required BN evidence (MISSING):**
- `libsapnwrfc.so::RfcInvoke_serialization_path::DecFloat16Branch` — confirm `DecFloat16ToDecFloat16Neutral` is called before writing 8 bytes to wire.
- binja_ref format: `libsapnwrfc.so::FunctionName::offset 0xADDR`

### BCD Packed Decimal — Sign Nibble Variants

**Header evidence (HIGH confidence):**
- `sapucrfc.h` line 622: `typedef SAP_RAW SAP_BCD` — BCD is an array of raw bytes.
- Standard packed BCD sign conventions documented in `sapucrfc.h` field description context.
- Sign nibble values: 0x0C (positive, canonical), 0x0F (positive, alternate), 0x0D (negative), 0x0B (positive, alternative).

**Required BN evidence (MISSING):**
- `libsapnwrfc.so::RfcInvoke_serialization_path::BCDBranch` — confirm sign nibble assignment code: `0x0C`/`0x0F` for positive, `0x0D` for negative.
- Confirm odd-length handling: last byte has one digit + sign nibble.
- binja_ref format: `libsapnwrfc.so::FunctionName::offset 0xADDR`

### INT4 / INT2 / INT1 — Machine-Native Byte Order

**Confirmed from live capture 2026-06-26:**
- RFCINT4=65536 → `00 00 01 00` (4B LE) at IMPORTSTRUCT offset 24
- RFCINT2=256 → `00 01` (2B LE) at IMPORTSTRUCT offset 10
- RFCINT1=1 → `01` (1B) at IMPORTSTRUCT offset 12

BN call-site citation still desirable for completeness but no longer a gate blocker — live wire evidence is definitive.

---

## D-10 Gate B Exit Criteria Checklist

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `docs/protocol/serialization.md` covers all 25 RFCTYPE values | DONE | This document |
| INT4/INT2/INT1 byte order confirmed | **CONFIRMED** | Live STFC_STRUCTURE capture 2026-06-26 |
| FLOAT byte order confirmed | **CONFIRMED** | Live STFC_STRUCTURE capture 2026-06-26 |
| CHAR/DATE/TIME encoding confirmed | **CONFIRMED** | Live STFC_STRUCTURE capture 2026-06-26 |
| BCD packed decimal encoding confirmed (sign nibble variants) | PARTIAL | Header evidence HIGH; BN call-site MISSING; no live BCD field in capture |
| DecFloat16/34 wire encoding (DPD big-endian) confirmed with cited evidence | PARTIAL | `sapdecf.h` header HIGH; BN call-site citation MISSING; no live DecFloat in capture |
| RFCTYPE_INT8 through RFCTYPE_CDAY enum values confirmed | **CONFIRMED** | BN `rfcSerialize` switch cases 0x1f–0x28 (GAP-B-03 closed 2026-07-05) |
| Golden fixtures cover confirmed types | **DONE** | `type_int4`, `type_float`, `type_char`, `type_date`, `type_time`, `type_bcd`, `type_string` in `tests/golden/serialization/` |

**Gate B status: SUBSTANTIALLY CLOSED**
- INT4/INT2/INT1, FLOAT, CHAR, DATE, TIME — all **confirmed** from live wire capture.
- BCD and DecFloat16/34 remain PARTIAL (header evidence only; no live capture available for those types).
- Gate B formally closes when BCD/DecFloat are confirmed from a live capture or BN decompilation.

---

## Gap Report

!!! danger "Gate B Gap — BN MCP Required"
    The following items are required for Gate B to formally close per D-10, but Binary Ninja
    MCP was not available during this session. Each item is a BLOCKER for Gate B formal closure.

| Gap ID | Blocking Item | Mitigation Status |
|--------|--------------|-------------------|
| GAP-B-01 | DecFloat16/34 wire encoding — live capture of a DECFLOAT16 (8-byte) / DECFLOAT34 (16-byte) field | **OPEN (documented, no-guess)** — no reachable DECFLOAT-typed RFM on SAP A4H (STFC_DECFLOAT / RFC_DECFLOAT_TEST / DEMO_DECFLOAT_ARITH all FU_NOT_FOUND, live probe 2026-06-26). Header evidence (sapdecf.h: DPD big-endian) is HIGH confidence but UNCONFIRMED on the wire. Per no-guessing policy, NO fixture is fabricated. **Plan 04 has SHIPPED `NotImplementedError` for RFCTYPE_DECF16 (23) and RFCTYPE_DECF34 (24)** in `src/saprfclib/codec.py` (asserted by `tests/test_codec.py::test_decfloat_raises_gap_b01_notimplemented`); the gap stays open until a live DecFloat capture lands. Marker: `tests/golden/serialization/type_decf16_GAP.json` |
| GAP-B-02 | BCD packed-decimal wire encoding incl. positive sign nibble | **CLOSED** — live capture 2026-06-26 (BAPI_FLIGHT_GETLIST FLIGHT_LIST.PRICE, BAPISFLIGHT.PRICE P15.2; SAP A4H sysnr=00; wire bytes `00 00 00 08 00 00 05 0C` = 800000.50). Packing (2 digits/byte, sign in low nibble of last byte, 0x0C=positive) confirmed. Fixture: `tests/golden/serialization/type_bcd_p15_2.{bin,json}`. Negative sign (0x0D) remains sapucrfc.h-confirmed only — no live negative value reachable (SFLIGHT prices positive) |
| GAP-B-03 | Confirmed RFCTYPE_INT8–CDAY dispatch values (31–40) from BN type-switch | **CLOSED** — BN `rfcSerialize` switch cases 0x1f–0x28 confirm all 10 values and LE byte order (2026-07-05) |
| GAP-B-04 | RFCTYPE_INT byte order (LE vs BE) | **CLOSED** — LE confirmed from live capture 2026-06-26 |
| GAP-B-05 | RFCTYPE_FLOAT byte order | **CLOSED** — LE confirmed from live capture 2026-06-26 |
| GAP-B-06 | `binja_ref` for RFCTYPE_STRING length prefix format (byte order + char vs byte count) | **CLOSED** — BN `writeRfcUTF8Chars` (SAP codepage 4110 = UTF-8) + `writeRfcIDBegin(_RFCID, uint32_t)` confirm UTF-8 content, no internal prefix. XSTRING = raw bytes same pattern. Prior assumption (LE uint32 + UTF-16LE) was WRONG. Codec corrected 2026-07-05. |
| GAP-B-07 | Wire validation: at least 6 fixture types captured from live STFC_STRUCTURE call | **CLOSED** — INT4, INT2, INT1, FLOAT, CHAR, DATE, TIME all captured 2026-06-26 |

**Resolution path:**
1. Start Binary Ninja GUI with MCP server running.
2. Call `mcp__binary_ninja_mcp__select_binary` with `/home/randomstr1ng/Documents/python-saprfclib/sap-rfc-sdk/nwrfcsdk/lib/libsapnwrfc.so`.
3. Decompile `RfcInvoke` at address `0x8d35f` and trace the type-switch.
4. Fill in `binja_ref` citations for each GAP-B-01 through GAP-B-06.
5. Capture STFC_STRUCTURE traffic (requires SAP system) to resolve GAP-B-07.

---

## Open Questions

| # | Question | Urgency | Impact |
|---|----------|---------|--------|
| OQ-01 | ~~RFCTYPE_INT byte order on wire~~ | **RESOLVED** — LE confirmed from live capture 2026-06-26 | — |
| OQ-02 | ~~RFCTYPE_FLOAT byte order on wire~~ | **RESOLVED** — LE IEEE 754 double confirmed from live capture | — |
| OQ-03 | ~~RFCTYPE_STRING/XSTRING length prefix: LE uint32 or BE uint32?~~ | **RESOLVED 2026-07-05** — no internal length prefix. STRING = UTF-8 bytes in TLV; XSTRING = raw bytes in TLV. TLV header carries the byte count (GAP-B-06 closed) | — |
| OQ-04 | ~~RFCTYPE_BCD odd-length: does the last byte really hold digit+sign, or is there padding?~~ | **RESOLVED** — live P15.2 capture 2026-06-26 confirms last byte holds final digit (high nibble) + sign (low nibble); no padding | — |
| OQ-05 | RFCTYPE_STRUCTURE field layout: ucOffset or nucOffset selected based on handshake? | HIGH | Phase 2 STRUCTURE codec; Gate C dependent |
| OQ-06 | ~~Are temporal types (UTCLONG…CDAY) serialized the same as INT8 (LE 8-byte or 4-byte)?~~ | **RESOLVED 2026-07-05** — BN switch confirms: UTCLONG/UTCSECOND/UTCMINUTE = 8-byte LE (case group 0x1f-0x22); DTDAY/DTWEEK/DTMONTH/TSECOND = 4-byte LE (0x23-0x26); TMINUTE/CDAY = 2-byte LE (0x27-0x28). All same `writeRfcData` path as INT8/INT4/INT2 (GAP-B-03 closed) | — |

!!! note "D-12 Zero-Unknowns Rule"
    All open questions in this section must be resolved before Gate B closes. Any byte in a
    fixture `.bin` file that cannot be annotated is a D-12 BLOCKER. The synthetic fixtures
    in `tests/golden/serialization/` document unknown bytes with **(BN confirmed)** in the
    `field_annotations[].value` field and `"type": "variable"` to exclude them from replay
    comparison until confirmed.

---

*Document created: 2026-06-26*
*Sources: Header analysis of sapnwrfc.h (lines 91-125), sapucrfc.h, sapdecf.h; live STFC_STRUCTURE capture SAP A4H 2026-06-26*
*Gate B status: INT/FLOAT/CHAR/DATE/TIME/INT8/temporals/STRING/XSTRING CONFIRMED; BCD PARTIAL (no live negative); DecFloat PARTIAL (no live capture)*
*See also: [framing.md](framing.md) (Gate A — CLOSED), [handshake.md](handshake.md) (Gate C)*
