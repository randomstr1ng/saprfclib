# NI/CPIC Framing Layer

**Status:** CONFIRMED — BN decompilation + live Wireshark capture (2026-06-26).
**Gate A status:** CLOSED — BN evidence + golden fixtures committed (`tests/golden/framing/`).
**Confidence:** HIGH — Binary Ninja HLIL decompilation of NiIWrite/NiIRead + live STFC_CONNECTION capture on SAP A4H (SYS: A4H, Rel: 758).

---

## Overview

The SAP Network Interface (NI) layer is the lowest-level framing abstraction in the SAP RFC protocol
stack. It sits directly above TCP and provides message-boundary framing on the byte-stream TCP
transport. Every RFC message — function call, handshake packet, or PING — is wrapped in an NI frame.

The call chain from the application layer down to the wire:

```
RfcOpenConnection() / RfcInvoke()     — RFC API entry points
  → RfcFunction::rfcSerialize()       — serialize ABAP parameters into TLV records
  → RfcConnectionBase::writeRfcCallBegin()  — write COM_HEAD + session/call TLV records
  → NiBufSend() / NiWrite()           — NI handle lookup, then:
    → NiIWrite()                      — NI framing: prepend 4-byte BE length, scatter-gather write
      → SiSendV()                     — OS socket writev() syscall
```

NI framing is symmetric: `NiRead()` → `NiIRead()` strips the header before returning payload.

**Live capture finding (2026-06-26):** SAP NW RFC SDK (`pyrfc`) connects to port **3300** (SAP
Gateway = `3300 + sysnr`), NOT port 3200 (dispatcher). The Gateway adds a 76-byte APPC/CPI-C
transport header to each RFC data frame between the NI header and the RFC TLV stream. See
"APPC/Gateway Header" section below.

---

## NI Frame Format

### Wire Layout

```
Offset  Length  Type        Name            Notes
 0x00     4     uint32-BE   payload_length  Length of payload ONLY. Does NOT include these 4 bytes.
 0x04     N     bytes       payload         RFC message body (N = payload_length)
```

**Total frame size on wire:** `4 + payload_length` bytes.

### Evidence

Confirmed by BN MCP HLIL decompilation of `NiIWrite` (BN addr `0x7a9b80`):

```c
// NiIWrite write-path (BN addresses):
007a9c48   *(r12 + 0x7c) = r14.d           // NITAB.pending_data = dataLen (arg3)
007a9c50   *(r12 + 0x80) = 4               // 4 header bytes pending to write
007a9c59   rsi = zx.q(_bswap(r14.d))       // convert dataLen to big-endian
007a9c5b   *(r12 + 0x81) = rsi.d           // store BE length in NITAB tx header buf

// sub_7a9c9b scatter-gather write:
007a9dbf   iov[0].base = NITAB + 0x81      // 4-byte BE length (0x85 - 4 = 0x81)
007a9dec   SiSendV(sock, iov, 2, ...)      // 2 iovecs: header + payload
```

Confirmed by BN MCP HLIL decompilation of `NiIRead` (BN addr `0x7a9f60`):

```c
// NiIRead read-path:
007aa34d   *(r12 + 0x74) = 4               // expect 4 header bytes
007aa249   r8_7 = *(r12 + 0x75)            // read 4 received header bytes as uint32
007aa254   r8_8 = _bswap(r8_7)             // big-endian → host conversion
007aa257   *(r12 + 0x70) = r8_8            // store payload_length (host order)
```

`binja_ref: libsapnwrfc.so::NiIWrite::0x7a9c50`  
`binja_ref: libsapnwrfc.so::NiIWrite::0x7a9c59 (bswap — big-endian confirmed)`  
`binja_ref: libsapnwrfc.so::NiIRead::0x7aa34d (header = 4 bytes)`  
`binja_ref: libsapnwrfc.so::NiIRead::0x7aa254 (bswap — payload length, excludes header)`  
`source_file: /bas/754_REL/src/base/ni/nixxi.cpp line 0x1147`

### RAW_MODE

When `NITAB[0x6c] == 1`, the connection is in RAW_MODE: no NI header is sent or expected.
`NiIRead` sets `*(r12 + 0x74) = 0` and `*(r12 + 0x70) = 0` → direct byte stream with no framing.
Relevant for special internal connections; standard RFC uses framed mode.

---

## NI Control Messages

The NI layer handles 8-byte ASCII control messages before passing data to the RFC layer.
Source: `NiBufIProcMsg` at BN addr `0x7a6690`.

| Message      | Bytes (ASCII+NUL)       | Purpose                          |
|--------------|-------------------------|----------------------------------|
| `NI_PING\0`  | `4e 49 5f 50 49 4e 47 00` | NI-level keepalive ping          |
| `NI_PONG\0`  | `4e 49 5f 50 4f 4e 47 00` | Response to NI_PING              |
| `NI_RTERR\0` | `4e 49 5f 52 54 45 52 52` | Router error                     |
| `NI_ROUTEAVI`| `4e 49 5f 52 4f 55 54 45` | Route availability check         |

These are NI payloads of exactly 8 bytes. The NI header's `payload_length` = 8 for these.
Regular RFC data is passed through without inspection.

`binja_ref: libsapnwrfc.so::NiBufIProcMsg::0x7a6690`

---

## Full Wire Stack (Confirmed by Live Capture)

```
TCP stream
└── NI frame
    ├── [4B BE]   ni_payload_length        (excludes these 4 bytes)
    ├── [76B]     APPC/GW header           (SAP Gateway transport header, see below)
    ├── [4B]      rfc_stream_marker        (ffff0001=client request, 00000001=server response)
    ├── [12B]     COM_HEAD                 (ONLY on logon frame; absent from call frames)
    └── [N×6+]    TLV records              ([tag 2B][len 2B][data][tag 2B], see TLV section)
                  └── [6B]   terminator   (tag=0xFFFF, len=0)
```

**Port:** SAP Gateway at `3300 + sysnr` (e.g., sysnr=00 → port 3300).

---

## APPC/Gateway Header (76 bytes)

The SAP Gateway inserts a 76-byte header in every RFC data frame (type `06 CB`). This is the
APPC (Advanced Program-to-Program Communications) transport layer that CPI-C uses.

```
Offset  Length  Notes
  0      2      GW message type: 06=data CB=RFC_DATA
  2      2      Protocol version: 02 00
  4      4      Max NI message size BE uint32 (FF FF 00 00 in client frames)
  8      2      [UNKNOWN] zeros / CPIC internal
 10      1      Sub-protocol version (0x01 in registration response)
 11      5      [UNKNOWN] zeros / CPIC internal
 16      4      CPIC flags word BE uint32 (0xC0000000 in registration response)
                  bit 0 of byte[16]: if set, copy 4 bytes from APPCHDR6[0x45] to
                  CONV_PROTO handle (BN STIAsRcvFromGw 005adc5d / A7nToUcn 005adc73)
 20      1      [UNKNOWN]
 21      1      Frame sub-type (0x06 in registration response; echoed as *rsi_6=6
                  by STIAsRcvFromGw 0059a4cb)
 22      2      [UNKNOWN] zeros
 24      4      CPIC handle/sequence (0x00000175 = 373 in registration response)
 28      2      [UNKNOWN] zeros
 30      1      [UNKNOWN] (0x01 in registration response)
 31      1      [UNKNOWN] (continuation of above field or padding)
 32      1      [UNKNOWN]
 33      1      [UNKNOWN]
 34      1      CPIC rc-valid flags (bit 0x10: rc fields at [32]/[36] are valid;
                  0x05 in registration response → bit clear = no error info)
 35      1      [UNKNOWN]
 36      4      CPIC return code BE int32 (0 = success); checked by STIAsRcvFromGw
                  at 0059a4c8 / bswap 0059a4d0
 40      4      Additional CPIC status BE int32; checked by STIAsRcvFromGw 0059a4eb
 44      8      GW connection handle: 8-byte ASCII decimal (e.g. "75568442")
                  assigned by the gateway; extracted at APPCHDR6[0x28..0x2f]
 52     12      RFC library name + version (e.g. "NWRFC   10.20.30", null-padded)
 64      8      SAP GW service / dispatcher name (e.g. "sapdp00 ", null-padded)
 72      4      Trailing bytes (0x49 0x01 0x00 0x00 in registration response)
```

`binja_ref: libsapnwrfc.so::STIAsRcvFromGw::0059a4c8 (APPCHDR6[0x20] = CPIC rc)`
`binja_ref: libsapnwrfc.so::STIAsRcvFromGw::0059a4d0 (bswap → host-order rc)`
`binja_ref: libsapnwrfc.so::STIAsRcvFromGw::0059a4eb (rc-valid flag check at [0x1e])`
`binja_ref: libsapnwrfc.so::STALLC::005adc5d (flags[0x10] bit-0 check)`
`binja_ref: libsapnwrfc.so::STALLC::005adc73 (A7nToUcn handle copy from [0x45])`
`source: gw_connect_response.bin golden fixture + BN decompile of STALLC / STIAsRcvFromGw`

**Key observation from capture:**
- All client→server RFC data frames share an **identical** 76-byte APPC header within a session
  (only the connection handle changes between sessions).
- Server→client frames have variable content in bytes 10-75 (session state, CPIC return codes, etc.)
- The header immediately follows the 4-byte NI header and precedes the RFC TLV stream.

The GW handshake (frames 4-13 in the session) uses different message types (`02 03`, `06 01`,
`06 0F`, `06 05`) for session establishment. `06 CB` = RFC data appears only after handshake.

**Implementation note:** Only bytes [44..51] (the GW handle) are consumed by `session.py`
(`_GW_HANDLE_OFFSET = 40`, `_GW_HANDLE_LEN = 8`, measured from start of NI payload). Bytes [8-39]
are CPIC internal state that the SDK processes but our implementation does not need to parse.
Fields [0x20..0x23] (CPIC rc) and [0x24..0x27] (additional status) are only non-zero on error;
successful registration returns zeros at both positions.

---

## RFC Marker (4 bytes)

```
Client request:  FF FF 00 04   (current binary: NW RFC SDK installed on A4H Rel. 758)
Server response: 00 00 00 04
```

Immediately follows the APPC header (at frame offset 80, i.e. NI[4] + GW[76]).
The `FF FF` vs `00 00` high bytes discriminate client→server from server→client frames.
The low 2 bytes (`00 04`) derive from `CONV_PROTO[0x1c] = 0x0400` bswapped to 0x0004
(see BN STISendToGw — bn-re-findings.md).

**Version note:** The golden fixture `stfc_connection_request.bin` was captured from a
different SDK version and shows `FF FF 00 01` at this position. The current installed
binary (confirmed by BN + strace) uses `FF FF 00 04` for all client frames.

---

## RFC Message Format (NG-RFC)

The RFC TLV stream (after APPC header + RFC marker) carries the RFC message. For NG-RFC
(next-generation) connections, the structure is:

```
Offset  Length   Name          Notes
 0x00    12      COM_HEAD      RFC message eyecatcher (EBCDIC "RFC" + padding)
                               ONLY present on the first (logon) frame of a session.
 0x0C    var     TLV records   Session + call data in tagged format
```

**IMPORTANT:** COM_HEAD appears **only on the logon frame** (session establishment). RFC function
call frames (STFC_CONNECTION, etc.) start the TLV stream directly after the RFC marker — no
COM_HEAD. This was confirmed by live capture: COM_HEAD found only in frame 14 (logon); all
subsequent frames (16, 19, 21, ...) start TLV immediately.

### COM_HEAD (12 bytes)

```
Hex:  D9 C6 C3 F0 F0 F0 F0 F0 F0 F0 F0 F0
```

Decoded as EBCDIC:
- Bytes 0-2: `D9 C6 C3` = `R F C` (EBCDIC code points for "RFC")
- Bytes 3-11: `F0` × 9 = `0 0 0 0 0 0 0 0 0` (EBCDIC digit '0')
- Full string: `"RFC000000000"` in EBCDIC

Trace variant (`TRACE_COM_HEAD`): byte 11 = `E3` = EBCDIC 'T' → `"RFC00000000T"`.

Evidence: hexdump of `.rodata` section in `libsapnwrfc.so`:

```
nm addr 0x3e4648 / BN addr 0x7e4648 (COM_HEAD):
  D9 C6 C3 F0 F0 F0 F0 F0 F0 F0 F0 F0

nm addr 0x3e4638 / BN addr 0x7e4638 (TRACE_COM_HEAD):
  D9 C6 C3 F0 F0 F0 F0 F0 F0 F0 F0 E3
```

Written by `RfcConnectionBase::writeRfcSessionHeader` (BN `0x554658`) on NG-RFC connections only:
```c
if (*(*(conn + 0x1c80) + 0x10) == 1)   // ng-format flag
    writeBytes(conn, &COM_HEAD);         // or TRACE_COM_HEAD when trace enabled
```

`binja_ref: libsapnwrfc.so::RfcConnectionBase::writeRfcSessionHeader::0x554658`  
`binja_ref: libsapnwrfc.so::COM_HEAD::0x7e4648 (rodata)`

### TLV Record Format

Each piece of RFC session/call data is encoded as a tagged record. Source: `writeRfcIDBegin`
(BN `0x551560`) and `writeRfcIDEnd` (BN `0x5515da`).

**Standard record (length < 65535):**
```
+--------+--------+----------------+--------+
| tag BE | len BE |    data        | tag BE |
|  2 B   |  2 B   |   len bytes    |  2 B   |
+--------+--------+----------------+--------+
```

**Extended record (length ≥ 65535, i.e., len field = 0xFFFF):**
```
+--------+------+----------+----------------+--------+
| tag BE | FFFF | ext-len  |    data        | tag BE |
|  2 B   | 2 B  |   4 B BE |   ext-len B    |  2 B   |
+--------+------+----------+----------------+--------+
```

Tag encoding: `writeRfcIDBegin` applies `rol16(tag, 8)` (= byte-swap) then writes as uint16 LE
→ net result: tag stored big-endian on wire.

Each record has BOTH an opening marker (with length) and a closing marker (same tag, no length).
Empty record (length 0): `[tag BE 2B] [00 00] [tag BE 2B]` = 6 bytes total.

`binja_ref: libsapnwrfc.so::RfcConnectionBase::writeRfcIDBegin::0x551560`  
`binja_ref: libsapnwrfc.so::RfcConnectionBase::writeRfcIDEnd::0x5515da`

### Known TLV Tags

Sources: BN decompilation of `writeRfcSessionHeader` (BN `0x554658`) + `writeRfcCallBegin`
(BN `0x554a10`) + live captures (STFC_CONNECTION, STFC_EXCEPTION, STFC_DEEP_TABLE, RFC_READ_TABLE).

| Tag (hex) | Source      | Role                                                                  |
|-----------|-------------|-----------------------------------------------------------------------|
| 0x000b    | capture     | RFC version string (e.g. "754" UTF-16LE)                             |
| 0x0101    | BN          | Session info (version, codepage)                                      |
| 0x0102    | capture     | Function name (UTF-16LE, e.g. "STFC_CONNECTION")                     |
| 0x0103    | BN          | Connection flags (4B BE uint32)                                       |
| 0x0106    | BN          | Protocol version                                                      |
| 0x0130    | capture     | Program name (UTF-16LE, e.g. "SAPLSTFC", padded to 80 bytes)        |
| 0x0131    | BN          | EPP (Extended Performance Profile)                                    |
| 0x0160    | BN          | Int16 field                                                           |
| 0x0201    | capture     | Parameter name (UTF-16LE, scalar IMPORTING/EXPORTING pair)           |
| 0x0203    | capture     | Parameter value CHAR (UTF-16LE, fixed-width space-padded)            |
| 0x0205    | capture     | Output table/param declaration (name UTF-16LE, one per return param) |
| 0x0301    | capture     | TABLE param name (UTF-16LE) — binary row format                      |
| 0x0302    | capture     | TABLE row descriptor (8 bytes; contains row count + row size)        |
| 0x0303    | capture     | TABLE type descriptor (402 bytes; from RFC_GET_FUNCTION_INTERFACE)   |
| 0x0304    | capture     | TABLE row data (UTF-16LE, fixed-width padded to ABAP row length)     |
| 0x0330    | capture     | TABLE header (4 bytes; part of binary TABLE encoding)                |
| 0x0337    | BN          | Marker / empty record                                                 |
| 0x0401    | capture     | ABAP exception key/name (UTF-16LE, e.g. "EXAMPLE")                  |
| 0x0417    | capture     | ABAP exception number (UTF-16LE, 3 chars, e.g. "000")               |
| 0x0420    | capture     | RFC return code (4B BE uint32; 0=success)                            |
| 0x0421    | BN          | Auth / call context                                                   |
| 0x0500    | capture     | Call-end / response-start marker (empty record)                      |
| 0x0502    | BN+capture  | Call-start marker (empty on call frames)                             |
| 0x0503    | capture     | Response flag 2 (empty record) [UNKNOWN]                             |
| 0x0504    | BN          | Function call begin (type A)                                         |
| 0x0512    | BN+capture  | Parameter section start / end of RFC exchange                        |
| 0x0513    | BN          | Function call begin (type B)                                         |
| 0x0514    | BN+capture  | Session token / connection ID (16B binary, random per session)       |
| 0x0667    | capture     | Float64 LE field [UNKNOWN purpose; value varies by session]          |
| 0x3c02    | capture     | BASXML section marker (empty; `<` = 0x3C, `,` = 0x02)               |
| 0x3c05    | capture     | BASXML content — raw ASCII XML (NOT UTF-16LE)                        |
| 0xFFFF    | capture     | TLV stream terminator (empty record, mandatory last)                 |

---

## RFC Function Call Sequence

Source: `RfcFunction::rfcSerialize` (BN `0x4af228`) → `writeRfcCallBegin` (BN `0x554a10`)
+ confirmed by live STFC_CONNECTION capture.

### Request (client → server)

```
NI header (4B) + APPC header (76B) + RFC marker ffff0004 (4B)
└── TLV stream:
    0x0502  len=0          call-start marker
    0x000b  len=6          RFC version "754" (UTF-16LE)
    0x0102  len=30         function name "STFC_CONNECTION" (UTF-16LE)
    0x0512  len=0          parameter section start
    0x0205  len=16         export param decl "ECHOTEXT" (UTF-16LE)   } one per
    0x0205  len=16         export param decl "RESPTEXT" (UTF-16LE)   } export param
    0x0201  len=16         import param name "REQUTEXT" (UTF-16LE)   }
    0x0203  ext len=510    import param value (CHAR(255) UTF-16LE, space-padded)
    0xFFFF  len=0          TLV stream terminator
```

### Response (server → client)

```
NI header (4B) + APPC header (76B) + RFC marker 00000004 (4B)
└── TLV stream:
    0x0500  len=0          call-end / response-start marker
    0x0503  len=0          response flag [UNKNOWN]
    0x0514  len=16         session token (16B binary)
    0x0420  len=4          return code uint32 BE (0=success)
    0x0512  len=0          parameter section start
    0x0205  len=16         export param decl (schema — echos request)
    ...
    0x0201  len=16         result param name (UTF-16LE)
    0x0203  ext len=510    result param value (CHAR(255) UTF-16LE, space-padded)
    ...                    (one name/value pair per output param)
    0x0130  len=80         calling program name "SAPLSTFC" (UTF-16LE padded)
    0x0667  len=8          [UNKNOWN]
    0xFFFF  len=0          TLV stream terminator
```

`binja_ref: libsapnwrfc.so::RfcConnectionBase::writeRfcCallBegin::0x554a10`

### Exception Response (server → client when ABAP exception raised)

Confirmed from live STFC_EXCEPTION call capture (2026-06-28). Golden fixture:
`tests/golden/framing/stfc_exception_response.bin` (128 bytes).

```
NI header (4B) + APPC header (76B) + RFC marker 00000004 (4B)
└── TLV stream:
    0x0500  len=0          call-end marker (empty, with suffix)
    0x0417  len=6          exception number: 3 UTF-16LE chars, e.g. "000"
    0x0401  len=14         exception key/name: N UTF-16LE chars, e.g. "EXAMPLE"
    0xFFFF  len=0          TLV stream terminator
```

**Note:** No 0x0503 or 0x0514 tags on exception response — the frame is minimal.
The exception KEY matches the ABAP RAISE statement (`RAISE EXAMPLE`).
The exception NUMBER is the ABAP MESSAGE number (3-digit "000" when no explicit message).

### Server registration (RfcRegisterServer → gateway)

Confirmed from BN decompilation of `RfcRegisterServer` (BN `0x77c550`) →
`CpicConnection::registerAsServer_SM` (`0x4ff35c`) → `SAP_CMREGTP3` → `STIRegTp`
(`0x798a70`) → `GwIConnect` (`0x7a0c80`), and live capture
(`tests/golden/framing/server_registration_request.bin`, 457B incl. NI header).
Full byte/field table in `.planning/bn-re-findings.md` §"Server registration &
inbound dispatch".

`STIRegTp(tpname=PROGRAM_ID, gwhost, gwserv, ...)` validates: PROGRAM_ID non-empty,
≤64 chars, no `*`; gwhost ≤2048 chars; gwserv non-empty. It then calls
`GwIConnect(0xb, gwhost, NULL, gwserv, hostname, &addr, PROGRAM_ID, ..., 0xffff,
"1100", ...)`.

**Registration request (server → gateway)** — the same 0x0601 GW_CONNECT APPCHDR6
frame the client emits (built by the STIInit-family builder), program_id-independent
on the wire:

```
NI header (4B) + APPCHDR6 (0x0601 GW_CONNECT)
  [0]      0x06            GW frame
  [1]      0x01            GW_CONNECT type
  [10]     0x01 / [16] 0xC0 / [21] 0x04 / [22] 0x00   STIInit constants
  [40:48]  8 spaces        no GW handle yet on outbound connect
  [48:56]  "NWRFC   "      remote RFC partner LU name (NOT the PROGRAM_ID)
  [76:80]  ffff ffff       request marker (ACK flips [78:80] → 0004)
  variable: local IP / NI hostname / service / OS user / time() blob @ [122:138]
```

> **PROGRAM_ID is NOT carried in this 0x0601 frame** (verified: it appears in no
> encoding in the capture). The "NWRFC" string is the fixed partner LU name. The
> PROGRAM_ID/tpname is conveyed to the gateway by the follow-up `SAP_CMACCPTP3`
> accept exchange (Wave 2). RFC marker direction: `ffffXXXX` = request,
> `0000XXXX` = the gateway-accepted reply.

**Registration ACK (gateway → server)** — echoes the request with: [21] 0x04→0x06
(acceptance flag), [40:48] = gateway-assigned ASCII connection handle (e.g.
`36964135`), [78:80] ffff→0004 (accepted tail).

**Inbound call (gateway → registered server)** reuses the 06-family data frame
(`0x060F` data + `0x0605` GW_DONE) carrying the assigned handle and the peer IP;
`RfcListenAndDispatch` (`0x77c680`) reads it via the same `readRfcChars`/
`rfcDeserialize` codepath as the client response. All inbound bytes are
peer-influenced and untrusted (parse with the bounds-checked TLV walker).

### CHANGING Parameter Encoding

Confirmed from live STFC_CHANGING capture (2026-06-28). Golden fixtures:
`tests/golden/framing/stfc_changing_request.bin` (260B),
`tests/golden/framing/stfc_changing_response.bin` (336B).

**CHANGING params use the SAME `0x0201 + 0x0203` tag pair as IMPORTING/EXPORTING.**
The direction (IMPORT / EXPORT / CHANGING) is determined entirely by PARAMCLASS metadata
from `RFC_GET_FUNCTION_INTERFACE` ('I'/'E'/'C') — no distinct TLV tag exists for CHANGING.

CHANGING params appear in BOTH the request (call-time value) AND the response (post-call value):

```
Client → server (STFC_CHANGING: START_VALUE=10, COUNTER=1):
    0x0502  len=0          call-start marker
    0x000b  len=6          '754' (version)
    0x0102  len=26         'STFC_CHANGING' (function name)
    0x0512  len=0          param section start
    0x0205  len=14         'COUNTER' (declare as export: will be returned)
    0x0205  len=12         'RESULT'  (declare as export: will be returned)
    0x0201  len=14         'COUNTER'     ← CHANGING param (PARAMCLASS='C')
    0x0203  len=4          01 00 00 00   ← value = 1 (INT4 LE)
    0x0201  len=22         'START_VALUE' ← IMPORTING param (PARAMCLASS='I')
    0x0203  len=4          0a 00 00 00   ← value = 10 (INT4 LE)
    0xFFFF  len=0          terminator

Server → client (response: COUNTER=2, RESULT=11):
    0x0500  len=0          call-end marker
    [session tags 0x0503, 0x0514, 0x0420, 0x0512]
    0x0205  len=12         'RESULT'
    0x0205  len=14         'COUNTER'
    0x0201  len=12         'RESULT'     ← EXPORTING param
    0x0203  len=4          0b 00 00 00  ← value = 11 (INT4 LE)
    0x0201  len=14         'COUNTER'    ← CHANGING param (new value)
    0x0203  len=4          02 00 00 00  ← value = 2 (INT4 LE)
    0x0130  len=80         'SAPLMRFC' (program name)
    0x0667  len=8          [UNKNOWN]
    0xFFFF  len=0          terminator
```

**Scalar type encoding in 0x0203 values:**
- `INT1` (byte): 1 byte LE
- `INT2` (short): 2 bytes LE
- `INT4` (int): 4 bytes LE — e.g. `0a 00 00 00` = 10
- `CHAR(n)` (ABAP CHAR): `2n` bytes UTF-16LE, space-padded — e.g. CHAR(255) = 510 bytes
- `FLOAT` (double): 8 bytes IEEE-754 double LE
- `RAW(n)` (ABAP RAW): `n` bytes verbatim
- `DATE` (YYYYMMDD): 16 bytes UTF-16LE
- `TIME` (HHMMSS): 12 bytes UTF-16LE

### STRUCTURE Parameter Encoding

Confirmed from STFC_STRUCTURE capture (2026-06-28). Golden fixtures:
`tests/golden/framing/stfc_structure_request.bin` (526B),
`tests/golden/framing/stfc_structure_response.bin` (1438B).

STRUCTURE params (ABAP structures) use the same `0x0201 + 0x0203` pair as scalars.
The value is the raw binary struct (each field encoded per its ABAP type, in declaration order,
no padding between fields beyond each field's natural size). Length = sum of field byte widths.

```
Client → server (IMPORTSTRUCT with RFCTEST struct):
    0x0201  len=24     'IMPORTSTRUCT' (param name)
    0x0203  len=264    [raw binary: RFCFLOAT(8B) + RFCCHAR1(2B) + RFCINT2(2B) + ...]
```

The server echos the struct back in ECHOSTRUCT via the same `0x0201 + 0x0203` encoding.

### TABLE Parameter Encoding

Two formats observed for TABLE parameters, depending on param direction and type.

#### BASXML format (0x3c02 / 0x3c05) — heterogeneous / STRING-containing tables

Used when tables contain STRING/XSTRING fields or when `REMOTE_BASXML_SUPPORTED` capability
is negotiated. Confirmed from STFC_DEEP_TABLE capture (2026-06-28). Golden fixtures:
`tests/golden/framing/stfc_deep_table_request.bin` (441B),
`tests/golden/framing/stfc_deep_table_response.bin` (1144B).

```
Client → server (IMPORTING table with rows):
    ...
    0x0205  len=20         expected export table name "EXPORT_TAB" (UTF-16LE)
    0x3c02  len=0          BASXML section start (marker, empty)
    0x3c05  len=12         raw ASCII: <IMPORT_TAB>
    0x3c05  len=217        raw ASCII: <item><I>1</I><C>ROW01</C><STR>string1</STR>...</item>...
    0x3c02  len=0          BASXML section end (marker, empty)
    0xFFFF  len=0          TLV terminator

Server → client (EXPORTING table with rows in response):
    0x0205  len=20         exported table name "EXPORT_TAB"
    0x0205  len=16         exported scalar name "RESPTEXT"
    0x3c02  len=0          BASXML section start
    0x3c05  len=12         raw ASCII: <EXPORT_TAB>
    0x3c05  len=282        raw ASCII: <item>...</item><item>...</item>...
    0x3c02  len=0          BASXML section end
    0x0201  len=16         scalar name "RESPTEXT" (UTF-16LE)
    0x0203  len=510        scalar value (UTF-16LE, space-padded)
    ...
```

**BASXML values** (0x3c05) are raw ASCII/UTF-8 XML, NOT UTF-16LE.
The tag prefix `0x3c` = `<` is the ASCII '<' character — a mnemonic, not a coincidence.

XML structure per table: `<TABLE_NAME><item><field>val</field>...</item>...</TABLE_NAME>`
XSTRING fields are base64-encoded within the XML.

#### Binary format (0x0301 / 0x0302 / 0x0304) — flat CHAR-based TABLES params

Used for TABLES parameters with flat structure (no STRING/XSTRING). Confirmed from
RFC_READ_TABLE capture (2026-06-28). Golden fixtures:
`tests/golden/framing/rfc_read_table_request.bin` (354B),
`tests/golden/framing/rfc_read_table_response.bin` (6091B).

```
Server → client (TABLES param with rows):
    0x0301  len=8          table name "DATA" (UTF-16LE)
    0x0330  len=4          table header [UNKNOWN; 4 bytes]
    0x0302  len=8          row descriptor [UNKNOWN; 8 bytes: contains row count + width]
    0x0304  len=1024       row 1 data (UTF-16LE, padded to ABAP table row width)
    0x0304  len=1024       row 2 data (UTF-16LE, padded to ABAP table row width)
    ...                    one 0x0304 per row
    0x0301  len=12         next table name "FIELDS"
    0x0330  len=4          ...
    0x0302  len=8          ...
    0x0304  len=206        FIELDS row (UTF-16LE, padded)
    ...
```

Row data is fixed-width UTF-16LE, padded to the ABAP table row length with spaces.
The ABAP row width determines the `0x0304` value length (e.g. 512 chars = 1024 bytes for RFC_READ_TABLE.DATA).

---

## CPIC / Gateway Layer Clarification

**Updated by live capture:** The initial BN analysis concluded "no CPIC header on wire." This was
incomplete — `CpicConnection` is a state machine, but the **SAP Gateway transport** (APPC layer)
DOES add a 76-byte header to every RFC data frame when connecting via port 3300.

The correct picture:

```
Wire = NI(4B) + APPC_GW_HEADER(76B) + RFC_MARKER(4B) + TLV_STREAM
```

The `B8nToCpicn` / `CpicnToB8n` functions in the binary handle internal data-format conversion
(B8n = 8-bit byte representation ↔ Cpicn = CPIC native format), not wire framing — original
conclusion stands for those specifically.

**Open question:** If connecting directly to port 3200 (SAP dispatcher, not Gateway), does the
APPC header still appear? The BN analysis suggested no CPIC header for direct connections, but
this has not been confirmed by capture. Port 3300 (Gateway) is what pyrfc uses by default.

---

## Python Reference Implementation

```python
import struct

NI_HEADER_SIZE = 4  # confirmed by BN decompilation

# RFC eyecatcher (EBCDIC "RFC000000000")
RFC_COM_HEAD = bytes([0xD9, 0xC6, 0xC3] + [0xF0] * 9)  # 12 bytes


def parse_ni_frame(data: bytes) -> tuple[int, bytes]:
    """Return (payload_length, payload). Raises ValueError if truncated."""
    if len(data) < NI_HEADER_SIZE:
        raise ValueError(f"Frame too short: {len(data)} < {NI_HEADER_SIZE}")
    (payload_length,) = struct.unpack_from(">I", data, 0)
    if len(data) < NI_HEADER_SIZE + payload_length:
        raise ValueError(f"Incomplete frame: have {len(data)}, need {NI_HEADER_SIZE + payload_length}")
    return payload_length, data[NI_HEADER_SIZE : NI_HEADER_SIZE + payload_length]


def build_ni_frame(payload: bytes) -> bytes:
    """Wrap payload in a 4-byte NI header."""
    return struct.pack(">I", len(payload)) + payload


def parse_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Parse one TLV record. Returns (tag, data, next_offset)."""
    tag = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    raw_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if raw_len == 0xFFFF:
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
    else:
        length = raw_len
    payload = data[offset : offset + length]
    offset += length
    close_tag = struct.unpack_from(">H", data, offset)[0]
    assert close_tag == tag, f"TLV close tag mismatch: {close_tag:#06x} != {tag:#06x}"
    offset += 2
    return tag, payload, offset
```

---

## Hex Example

**Source:** `tests/golden/framing/stfc_connection_request.bin` (740 bytes)
Live capture SAP A4H sysnr=00 port=3300, STFC_CONNECTION call.

**Note on offsets:** All frame offsets below are from byte 0 of the frame (including NI
prefix). GW header occupies bytes [0x04:0x50] = 76 bytes. RFC marker at [0x50:0x54].
TLV stream starts at [0x54].

```
Offset   Bytes                                    Field
──────── ──────────────────────────────────────── ────────────────────────────────────
0x0000:  00 00 02 e0                              NI payload_length = 736 (BE uint32)
0x0004:  06 cb 02 00 ff ff 00 00  00 00 00 00     APPC/GW header byte [0:11]
0x0010:  00 00 00 00 00 00 00 00  00 00 00 08     APPC/GW header byte [12:23]
0x0020:  00 00 05 0c 00 00 00 00  00 00 00 00     APPC/GW header byte [24:35]
0x002c:  37 35 35 36 38 34 34 32                  connection handle "75568442" (ASCII) [GW40:48]
0x0034:  00 00 00 00 00 00 00 00  ...×28 zeros    APPC/GW header trailing zeros
0x0050:  ff ff 00 01                              RFC stream marker (NOTE: this golden
                                                  was captured from older SDK; current
                                                  binary uses ff ff 00 04 — see RFC Marker section)
0x0054:  05 02 00 00 05 02                        TLV 0x0502 len=0 (call-start)
0x005a:  00 0b 00 06 37 00 35 00  34 00 00 0b     TLV 0x000b len=6 "754" (version)
0x0066:  01 02 00 1e                              TLV 0x0102 len=30 (func name open)
0x006a:  53 00 54 00 46 00 43 00  5f 00 43 00     "STFC_" (UTF-16LE)
0x0072:  4f 00 4e 00 4e 00 45 00  43 00 54 00     "ONNECT" (UTF-16LE)
0x007a:  49 00 4f 00 4e 00                        "ION" (UTF-16LE)
0x007d:  01 02                                    TLV 0x0102 close
0x007f:  05 12 00 00 05 12                        TLV 0x0512 len=0 (param section)
...      [export param declarations + REQUTEXT name/value pair]
0x02e6:  ff ff 00 00 ff ff                        TLV 0xFFFF len=0 (terminator)
```

See `tests/golden/framing/stfc_connection_request.json` for full field-by-field annotation.

---

## Open Questions

!!! note "RESOLVED: APPC/Gateway header (76 bytes) field layout — BN confirmed"
    Fields [8-39] decoded from BN decompile of `STIAsRcvFromGw` (0x799990) + `STALLC` (0x5ad5b5)
    against `gw_connect_response.bin` golden fixture. Key fields: [16]=flags, [21]=sub-type,
    [24-27]=CPIC handle/seq, [34]=rc-valid-flag, [36-39]=CPIC rc, [40-43]=additional status,
    [44-51]=GW handle. Our implementation only consumes [44-51]; all other fields are CPIC internal
    state that we do not need to parse. Full layout in "APPC/Gateway Header" section above.

!!! note "MEDIUM: Port 3200 (dispatcher) wire format"
    All captures used port 3300 (Gateway). If connecting directly to port 3200 (dispatcher),
    does the APPC header still appear? BN analysis suggested no CPIC header for direct connections.
    Confirm by capturing traffic on port 3200 vs port 3300 from same SAP system.

!!! note "LOW: COM_HEAD scope"
    COM_HEAD confirmed only in logon frame. Need to verify: is it also present in tRFC/qRFC/bgRFC
    first messages, or truly only in session establishment?

!!! note "LOW: Classic RFC (non-NG) wire format"
    NG-RFC uses COM_HEAD + TLV. Classic CPI-C connections (`CpicConnection` with non-NG flag)
    use a different format. SAP A4H Rel. 758 uses NG-RFC. Classic format deferred.

!!! note "LOW: Function name encoding confirmed"
    Live capture confirms function name (tag 0x0102) is UTF-16LE, not ASCII. ✓ Resolved.

---

## Phase 3 Gap Register (Transport, Session & Metadata)

These items were implemented in Phase 3 and confirmed or partially confirmed via live capture.
They are recorded here so future phases can close the remaining gaps.

### TRANS-02 — SAProuter NI_ROUTE prefix  [CONFIRMED 2026-06-27]

Wire format confirmed from live capture (`captures/phase03_saprouter_capture.py`):
`NI_ROUTE\0` (9B) + talk_mode(0x02) + 0x28 + version(0x02) + hop_count(4B BE) +
total_data_length(4B BE) + per-hop entries (entry_len[4B] + host\0 + svc[6B]) +
final destination (host\0 + svc[6B]). Golden fixture: `tests/golden/router/ni_route_payload.bin`.
Source: RESEARCH A1. Status: CLOSED.

### TRANS-03 — Message-server SAPMS group-logon redirect  [CLOSED — full frame parsed, pool selection deferred to Phase 5]

Live capture (`captures/phase03_msgserver_capture.py`, Phase 3) confirmed the exchange
completes and returns a working app-server redirect. Full `**MESSAGE**` frame parsing is
implemented in Phase 4 (`parse_sapms_server_list`, `src/saprfclib/router.py`) and validated
against the golden fixture `tests/golden/router/sapms_server_list.bin` (598 bytes, 3 entries,
wire-captured 2026-06-27). Connection pool load-balanced selection deferred to Phase 5.

**SAPMS MESSAGE Frame Layout** (server-list response, wire-captured 2026-06-27):

```
Offset  Size  Field              Notes
------  ----  -----              -----
 0       4    NI length prefix   BE uint32 = frame_total - 4. wire-captured.
 4      11    magic              "**MESSAGE**" (ASCII). wire-captured.
15       1    key                0x00. [ASSUMED] purpose unknown. wire-captured value.
16       1    version            0x04. wire-captured.
17       1    padding            0x00. wire-captured value.
18       1    sender_type        0x2D ('-') in server responses. wire-captured.
19      40    sender_name        Space-padded ASCII + null, 40 bytes total. wire-captured.
59      11    zeros              11 zero bytes. wire-captured value.
70       1    msg_type           0x03 = MSG_SERVER class. [ASSUMED] purpose. wire-captured.
71       1    direction          0x01 = server→client response. [ASSUMED]. wire-captured.
72      10    opcode_name        "MSG_SERVER" (ASCII, space-padded). wire-captured.
82      30    opcode_padding     30 space bytes. wire-captured.
112      2    unknown            0x0000. wire-captured value.
114      2    opcode_field       0x0500 in server-list response. [ASSUMED]. wire-captured.
116      2    sub_opcode         0x0403. [ASSUMED]. wire-captured.
118   N×160   server entries     N = (frame_total - 118) / 160. wire-captured entry size.
```

**Per-server entry layout** (160 bytes each, wire-captured from 3 entries):

```
Entry  Size  Field              Notes
-----  ----  -----              -----
  0     40   instance_name      Space-padded ASCII (e.g. "vhcala4hci_A4H_00"). wire-captured.
 40     40   hostname_string    Space-padded ASCII dotted-IPv4 or hostname. wire-captured.
 80     40   field3             [ASSUMED] secondary name / "tick-port" string. wire-captured.
120     15   unknown_zeros      Leading space(s) then zero bytes. wire-captured.
135      2   ffff_marker        0xFFFF. Confirmed in all 3 entries. wire-captured.
137      4   ip_addr_primary    4-byte BE IPv4 (e.g. 0xC0A85807 = 192.168.88.7). wire-captured.
141      4   ip_addr_secondary  Duplicate of primary. [ASSUMED]. wire-captured.
145      2   port               BE uint16; 0 = inactive, 0x0C80 = 3200. wire-captured.
147     13   trailing_flags     [ASSUMED] flags/load score. wire-captured values vary.
```

**Entry count**: `N = (frame_size - 118) / 160`. No confirmed count field in header — count inferred from remaining bytes. [ASSUMED] frame always contains whole entries (size % 160 == 0).

**Server selection**: First entry with port > 0 is the active application server.
`sysnr = (port - 3200) // 100` (e.g. port 3200 → sysnr 0).

**Golden fixture**: `tests/golden/router/sapms_server_list.bin` (598 bytes = 118 header + 3×160 entries).
Sidecar JSON: `tests/golden/router/sapms_server_list.json` (annotated field offsets; [ASSUMED] fields marked).

**Still-[ASSUMED] fields**: `key` (offset 15), `msg_type` / `direction` (70/71), `opcode_field` /
`sub_opcode` (114/116), `field3` in per-server entry (80-120), `ip_addr_secondary` (141),
`trailing_flags` (147), and the inferred-not-confirmed entry count mechanism.

### META-01 — RFC_GET_FUNCTION_INTERFACE result-table column layout  [CONFIRMED 2026-06-27]

Column layout confirmed from live capture (`captures/phase03_metadata_capture.py`):
12 columns — `PARAMCLASS, PARAMETER, TABNAME, FIELDNAME, EXID, POSITION, OFFSET, INTLENGTH,
DECIMALS, DEFAULT, PARAMTEXT, OPTIONAL`. EXID is a single-char string code ('C'=CHAR,
'I'=INT4, etc.); INTLENGTH and OFFSET are unicode byte values. The `_parse_params_row` parser
is live-verified. The uncached fetch via `get_function_desc` requires the Phase 4 RFC invoke
path (RESEARCH A3, META-01). Golden result: `captures/phase03_metadata_STFC_CONNECTION.json`.

### Logon password-hash (handshake tag 0x0117)  [CLOSED — Plan 04-01]

Tag 0x0117 (17 bytes) is NOT a hash — it is SAP's reversible `ab_scramble` byte cipher:
`seed(4B LE) + ab_scramble(password_bytes, seed)`. The 64-byte key table (`_AB_SCRAMBLE_KT`)
and algorithm were extracted from `libsapnwrfc.so` via Binary Ninja decompilation of
`ab_scramble` (BN addr `0x7099e6`) and verified against a live logon. Seed is stored
little-endian (x86 native), not big-endian. Status: CLOSED (Plan 04-01). Implemented in
`src/saprfclib/connection.py::_scramble_password`. See `docs/protocol/handshake.md` §"Password
scrambling" for the full derivation.

---

## Phase 4 Gap Register (Synchronous RFC Client MVP)

These items were investigated during Phase 4 but left as documented gaps for future phases.
Each entry records the gap ID, reason it was deferred, and the target phase for resolution.

### GAP-04-01: AbapSystemFailure rich-field set  [DEFERRED — Phase 5]

Decision D-16 (Plan 04-04): `AbapSystemFailure` exposes only `message: str | None` in Phase 4.
The full RFC_ERROR_INFO field set from `sapnwrfc.h` (rfcCode, abapMsgClass, abapMsgType,
abapMsgNumber, abapMsgV1..V4, group, key) is NOT parsed from the response TLV. The server
may send these fields in additional tags beyond 0x0420 (BN-TODO: identify the tags for
system-failure metadata). Phase 5 (or later) should extend `AbapSystemFailure` and the
parser to capture the full error context.

**Target:** Phase 5 (RFC Server) or Phase 8 (QoL). **Severity:** Low for v1 MVP.

### GAP-04-02: BN-TODO — Exception TLV semantic mapping (0x0401 vs 0x0417)  [DEFERRED — Phase 5]

Wire observation: 0x0417 = UTF-16LE 3-char string "000" (looks like message number);
0x0401 = UTF-16LE N-char string "EXAMPLE" (looks like exception key). Mapping was
confirmed empirically by matching `RAISE EXAMPLE` in ABAP source against the captured
key. However, BN decompilation of the RFC exception serializer has NOT confirmed:
- Whether 0x0401 is key (exception name) vs msg class
- Whether 0x0417 is message number vs exception number vs sequence number
- Whether additional tags carry abapMsgClass/Type/Number for ABAP MESSAGE exceptions

**Target:** Phase 5. **Severity:** Medium — AbapApplicationError field mapping may be
incorrect for MESSAGE-bearing exceptions. Affects CLIENT-05 accuracy.

### GAP-04-03: BN-TODO — TABLE binary encoding (0x0302 / 0x0330 layout)  [DEFERRED — Phase 5]

Wire capture confirmed: `0x0330` (4B, purpose unknown), `0x0302` (8B, contains row count
and row width), `0x0304` (fixed-width UTF-16LE row data). The exact byte positions for
row count and row width within the 8-byte 0x0302 value have NOT been BN-confirmed.
Current implementation assumes positions from pattern-matching; any discrepancy would
cause wrong row count / misaligned rows on binary TABLE parsing.

**Target:** Phase 5 (when TABLE round-trips are needed for RFC server). **Severity:** Medium.

### GAP-04-04: BASXML TABLE encoding not implemented  [DEFERRED — Phase 5]

Wire confirms two TABLE formats: BASXML (0x3c02/0x3c05 ASCII XML) for heterogeneous tables
(STRING/XSTRING fields) and binary (0x0301/0x0302/0x0304) for flat CHAR-based tables.
Phase 4 implementation emits binary format only. BASXML encode/decode is NOT implemented.
STFC_DEEP_TABLE response (golden fixture) uses BASXML — any FM returning a STRING-containing
table will produce a parse error.

**Target:** Phase 5 codec extension. **Severity:** High for FMs with STRING TABLE fields.

### GAP-04-05: Unsupplied CHANGING param wire behavior  [DEFERRED — Phase 5]

The CHANGING param encoding is confirmed: supplied CHANGING params use 0x0201 + 0x0203
(same as IMPORTING). However, it is UNCONFIRMED whether an unsupplied optional CHANGING
param is: (a) omitted from the request TLV entirely, or (b) sent as a zero-value placeholder.
Phase 4 implementation omits unsupplied params (same policy as IMPORTING/EXPORTING).
If SAP expects an explicit zero-value for CHANGING, some FMs may fail at the ABAP layer.

**Target:** Phase 5 (test against a FM with optional CHANGING). **Severity:** Low.

---

## Cross-References

- [serialization.md](serialization.md) — ABAP type encoding inside TLV data payloads (Gate B)
- [handshake.md](handshake.md) — Logon handshake TLV sequence (Gate C)
- [methodology.md](methodology.md) — RE workflow and how to extend this documentation
- [../../../.planning/phases/01-reverse-engineering-spike-protocol-spec/bn-decompilation-notes.md](../../.planning/phases/01-reverse-engineering-spike-protocol-spec/bn-decompilation-notes.md) — Full BN HLIL decompilation notes

---

*Gate A status: CLOSED — BN decompilation + live capture + golden fixtures committed*
*Last updated: 2026-06-28 (Phase 4 Plan 06: Phase 4 Gap Register added; password-hash gap closed; TRANS-03/META-01 closed)*
*Captures: SAP A4H Rel. 758, sysnr=00, port=3300*
