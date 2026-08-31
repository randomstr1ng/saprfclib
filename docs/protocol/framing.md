# NI/CPIC Framing Layer

**Status:** CONFIRMED — live capture (2026-06-26), golden fixtures committed under
`tests/golden/framing/`.
**Confidence:** HIGH — byte-exact `STFC_CONNECTION` capture against SAP NetWeaver 7.58,
replayed in CI.

---

## Overview

The SAP Network Interface (NI) layer is the lowest-level framing abstraction in the SAP RFC protocol
stack. It sits directly above TCP and provides message-boundary framing on the byte-stream TCP
transport. Every RFC message — function call, handshake packet, or PING — is wrapped in an NI frame.

The layering from the application down to the wire:

```
RFC call                     — function name + ABAP parameters
  → TLV serialization        — parameters encoded as tagged records
  → session/call records     — COM_HEAD (logon frame only) + session and call TLVs
  → NI framing               — prepend 4-byte big-endian length
    → TCP                    — a single writev() of header + payload
```

Framing is symmetric: the read path strips the 4-byte header before handing the payload up.

**Live capture finding (2026-06-26):** RFC connects to port **3300** (SAP Gateway =
`3300 + sysnr`), not port 3200 (dispatcher). The gateway adds a 76-byte APPC/CPI-C transport
header to each RFC data frame, between the NI header and the RFC TLV stream. See the
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

**Tier: live capture.** Every frame in `tests/golden/framing/` begins with a 4-byte
big-endian length whose value equals `len(frame) - 4`. The relationship holds across all
committed fixtures — request and response, minimum 128 bytes and maximum 6091 bytes — so the
header is fixed-width and the length excludes itself.

Both directions use the same framing: the read path consumes 4 bytes, byte-swaps them from
network order, and then reads exactly that many payload bytes.

```python
# The whole of NI framing, verified against every golden fixture
assert struct.unpack_from(">I", frame, 0)[0] == len(frame) - 4
```

The header and payload are written together in a single scatter-gather write, so a frame is
not observable in two pieces on a healthy connection — do not rely on that for parsing,
though: TCP may still split it, and `transport.py` reassembles.

### RAW_MODE

Some internal connection types run unframed — no length header in either direction. Standard
RFC always uses framed mode, and `saprfclib` implements only the framed path.

---

## NI Control Messages

The NI layer handles 8-byte ASCII control messages itself, before passing data up to the RFC
layer.

| Message      | Bytes (ASCII+NUL)       | Purpose                          |
|--------------|-------------------------|----------------------------------|
| `NI_PING\0`  | `4e 49 5f 50 49 4e 47 00` | NI-level keepalive ping          |
| `NI_PONG\0`  | `4e 49 5f 50 4f 4e 47 00` | Response to NI_PING              |
| `NI_RTERR\0` | `4e 49 5f 52 54 45 52 52` | Router error                     |
| `NI_ROUTEAVI`| `4e 49 5f 52 4f 55 54 45` | Route availability check         |

These are NI payloads of exactly 8 bytes — the NI header's `payload_length` is 8. Regular RFC
data is passed through without inspection.

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
                  bit 0 of byte[16]: when set, 4 bytes at [0x45] carry a conversation
                  handle
 20      1      [UNKNOWN]
 21      1      Frame sub-type (0x06 in registration response; echoed back by the peer)
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
 36      4      CPIC return code BE int32 (0 = success)
 40      4      Additional CPIC status BE int32
 44      8      GW connection handle: 8-byte ASCII decimal (e.g. "75568442")
                  assigned by the gateway
 52     12      RFC library name + version (e.g. "NWRFC   10.20.30", null-padded)
 64      8      SAP GW service / dispatcher name (e.g. "sapdp00 ", null-padded)
 72      4      Trailing bytes (0x49 0x01 0x00 0x00 in registration response)
```

*Source: `tests/golden/framing/gw_connect_response.bin` golden fixture, cross-checked against
the reference client's observed behaviour on the same exchange.*

**Key observation from capture:**
- All client→server RFC data frames share an **identical** 76-byte APPC header within a session
  (only the connection handle changes between sessions).
- Server→client frames have variable content in bytes 10-75 (session state, CPIC return codes, etc.)
- The header immediately follows the 4-byte NI header and precedes the RFC TLV stream.

The GW handshake (frames 4-13 in the session) uses different message types (`02 03`, `06 01`,
`06 0F`, `06 05`) for session establishment. `06 CB` = RFC data appears only after handshake.

**Implementation note:** Only bytes [44..51] (the GW handle) are consumed by `session.py`
(`_GW_HANDLE_OFFSET = 40`, `_GW_HANDLE_LEN = 8`, measured from the start of the NI payload).
Bytes [8-39] are CPIC internal state that `saprfclib` does not need to parse.
Fields [0x20..0x23] (CPIC rc) and [0x24..0x27] (additional status) are only non-zero on error;
successful registration returns zeros at both positions.

---

## RFC Marker (4 bytes)

```
Client request:  FF FF 00 04
Server response: 00 00 00 04
```

Immediately follows the APPC header (at frame offset 80, i.e. NI[4] + GW[76]).
The `FF FF` vs `00 00` high bytes discriminate client→server from server→client frames. The
low 2 bytes carry a conversation-protocol value, byte-swapped into `00 04`.

**Version note:** The golden fixture `stfc_connection_request.bin` was captured from an older
client version and shows `FF FF 00 01` here. Newer clients emit `FF FF 00 04` on all client
frames. Both are accepted by the systems tested; `saprfclib` emits `FF FF 00 04`.

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

Evidence: live capture — the 12-byte sequence appears at payload offset 80 of the logon frame
and nowhere else in the session. The trace variant is emitted only when the client has tracing
enabled, which is why it does not appear in the fixtures.

COM_HEAD is written on NG-RFC connections only; classic CPI-C connections do not carry it.

### TLV Record Format

Each piece of RFC session/call data is encoded as a tagged record, with a matched opening and
closing marker.

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

Tags are stored **big-endian** on the wire, unlike the ABAP scalar values they wrap.

Every record has BOTH an opening marker (carrying the length) and a closing marker (the same
tag, no length). An empty record is therefore 6 bytes: `[tag BE 2B] [00 00] [tag BE 2B]`.
The closing tag is a cheap structural check — `saprfclib` asserts it matches on every record,
which catches a desynchronised parse immediately rather than 200 bytes later.

### Known TLV Tags

Evidence column: **capture** = the tag was observed on the wire in a committed fixture;
**analysis** = the tag is known to exist from reference-client behaviour but has not yet been
seen in a capture, so its role is provisional.

Captures drawn on: STFC_CONNECTION, STFC_EXCEPTION, STFC_DEEP_TABLE, RFC_READ_TABLE,
STFC_CHANGING, STFC_STRUCTURE.

| Tag (hex) | Evidence    | Role                                                                  |
|-----------|-------------|-----------------------------------------------------------------------|
| 0x000b    | capture     | RFC version string (e.g. "754" UTF-16LE)                             |
| 0x0101    | analysis          | Session info (version, codepage)                                      |
| 0x0102    | capture     | Function name (UTF-16LE, e.g. "STFC_CONNECTION")                     |
| 0x0103    | analysis          | Connection flags (4B BE uint32)                                       |
| 0x0106    | analysis          | Protocol version                                                      |
| 0x0130    | capture     | Program name (UTF-16LE, e.g. "SAPLSTFC", padded to 80 bytes)        |
| 0x0131    | analysis          | EPP (Extended Performance Profile)                                    |
| 0x0160    | analysis          | Int16 field                                                           |
| 0x0201    | capture     | Parameter name (UTF-16LE, scalar IMPORTING/EXPORTING pair)           |
| 0x0203    | capture     | Parameter value CHAR (UTF-16LE, fixed-width space-padded)            |
| 0x0205    | capture     | Output table/param declaration (name UTF-16LE, one per return param) |
| 0x0301    | capture     | TABLE param name (UTF-16LE) — binary row format                      |
| 0x0302    | capture     | TABLE row descriptor (8 bytes; contains row count + row size)        |
| 0x0303    | capture     | TABLE type descriptor (402 bytes; from RFC_GET_FUNCTION_INTERFACE)   |
| 0x0304    | capture     | TABLE row data (UTF-16LE, fixed-width padded to ABAP row length)     |
| 0x0330    | capture     | TABLE header (4 bytes; part of binary TABLE encoding)                |
| 0x0337    | analysis          | Marker / empty record                                                 |
| 0x0401    | capture     | ABAP exception key/name (kernel 793; e.g. "FU_NOT_FOUND")            |
| 0x0402    | capture     | ABAP exception message text (kernel 752; e.g. "Logon data incomplete.") |
| 0x0403    | capture     | ABAP exception key/name (kernel 752; alternative to 0x0401)          |
| 0x0411    | capture     | Message variable V1                                                  |
| 0x0415    | capture     | Message class (2 chars, e.g. "00", "FL")                             |
| 0x0416    | capture     | Message type (1 char, e.g. "X", "E")                                 |
| 0x0417    | capture     | ABAP exception/message number (3 chars, e.g. "000", "341")           |
| 0x0418    | capture     | ABAP call-stack breadcrumb (`;W=…,E=…;S=…;D=…` — not parsed)         |
| 0x0420    | capture     | RFC return code (4B BE uint32; 0=success)                            |
| 0x0421    | analysis          | Auth / call context                                                   |
| 0x0500    | capture     | Call-end / response-start marker (empty record)                      |
| 0x0502    | capture+analysis  | Call-start marker (empty on call frames)                             |
| 0x0503    | capture     | Response flag 2 (empty record) [UNKNOWN]                             |
| 0x0504    | analysis          | Function call begin (type A)                                         |
| 0x0512    | capture+analysis  | Parameter section start / end of RFC exchange                        |
| 0x0513    | analysis          | Function call begin (type B)                                         |
| 0x0514    | capture+analysis  | Session token / connection ID (16B binary, random per session)       |
| 0x0667    | capture     | Server call duration: float64 LITTLE-endian, microseconds            |
| 0x3c02    | capture     | BASXML section marker (empty; `<` = 0x3C, `,` = 0x02)               |
| 0x3c05    | capture     | BASXML content — raw ASCII XML (NOT UTF-16LE)                        |
| 0xFFFF    | capture     | TLV stream terminator (empty record, mandatory last)                 |

---

## RFC Function Call Sequence

Confirmed by live STFC_CONNECTION capture. Golden fixtures:
`tests/golden/framing/stfc_connection_request.bin`, `stfc_connection_response.bin`.

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
    0x0667  len=8          server call duration — float64 LE, microseconds
    0xFFFF  len=0          TLV stream terminator
```

### RFCPING — CONFIRMED (2026-08-26)

`RFCPING` is an ordinary zero-parameter function call, not a special frame. It needs
the same GW header, RFC marker, TLV body and invoke footer as any other call; a bare
TLV body is rejected by the gateway, which reads the function name where it expects
the 76-byte header and answers with a plain-text error beginning `*ERR`.

Golden fixtures: `tests/golden/framing/rfcping_request.bin` (138 B),
`rfcping_response.bin` (236 B). Both were captured above the NI layer, so — unlike
the other framing fixtures — they carry **no 4-byte NI length prefix** and start at
the GW header. Captured from A4H kernel 793 / release 758, unicode, codepage 4103.

```
Request (client → server), 138 B total
APPC header (76B) + RFC marker ffff0004 (4B)
└── TLV stream (50 B):
    0x0502  len=0          call-begin marker
    0x000b  len=6          RFC version "754" (UTF-16LE)
    0x0102  len=14         function name "RFCPING" (UTF-16LE)
    0x0512  len=0          end of the call-begin block
    0xFFFF  len=0          TLV stream terminator
+ invoke footer (8B): 0x0000 | BE16 len(tlv)=0x32 | 0x0000 | 0x8500

Response (server → client), 236 B total
APPC header (76B) + RFC marker 00000002 (4B)
└── TLV stream:
    0x0500  len=0          response-start marker
    0x0503  len=0          response flag [UNKNOWN]
    0x0514  len=16         session token (16B binary)
    0x0420  len=4          return code uint32 BE (0 = success)
    0x0512  len=0          parameter section start (no parameters follow)
    0x0130  len=80         handling program "SAPLSYSU" (UTF-16LE, padded to 40 chars)
    0x0667  len=8          call duration — float64 LE, microseconds (138.0 here)
    0xFFFF  len=0          TLV stream terminator
```

Every record above is followed by its repeated close tag. Two consequences for any
reader, both of which produced real bugs (issue #7):

* **Strip the 80-byte GW header first.** Parsing from offset 0 reads `gw_version`
  (0x0200) as a TLV length, which surfaces as `length 512 exceeds remaining payload`.
* **Skip the repeated close tag.** The return code `0x0420` is the *fourth* record,
  not the first. A walk that does not skip close tags desynchronises by two bytes
  before it gets there and misreads every subsequent tag.

Note the response RFC marker is `00000002` here, where the STFC_CONNECTION response
above shows `00000004`. The marker value varies; the 80-byte strip keys off the
leading `0x06` GW-frame byte and is unaffected either way.

### XML-encoded table rows (0x3c02 / 0x3c05) — CONFIRMED (2026-08-28)

Some tables come back as plain-text XML instead of binary rows. An empty `0x3c02`
brackets the block on both sides and the XML is carried in `0x3c05` chunks:

```
0x0205 len=14   'ET_DATA'                     export declaration (UTF-16LE)
0x3c02 len=0                                  block begin
0x3c05 len=9    '<ET_DATA>'                   ASCII — NOT UTF-16LE
0x3c05 len=211  '<item><LINE>a|b|c</LINE></item></ET_DATA>'
0x3c02 len=0                                  block end
```

`RFC_READ_TABLE` uses this for `ET_DATA` when called with `USE_ET_DATA_4_RETURN='X'`,
the flag that avoids truncating STRING columns into `DATA`'s fixed work area. With
the flag set, `DATA` still arrives declared (`0x0301`/`0x0330`/`0x0302`) but carries
no rows.

Golden fixtures: `tests/golden/framing/rfc_read_table_response.bin` (empty table) and
`basxml_et_data_response.bin` (one populated row).

Two properties that are easy to get wrong:

* **The payload is ASCII.** Every other string-bearing tag in the protocol is
  UTF-16LE; decoding these chunks that way yields mojibake.
* **The fragments are one document split at arbitrary points, so only the first
  names the table.** In the capture above, chunk 2 begins `<item>` — re-deriving the
  name per chunk files the rows under a table called `item` and loses them.

Row shape observed is the shortcut form: one `<LINE>` element holding the whole
delimited row. The documented alternative puts one element per field. Both work under
the same rule — whatever elements an `<item>` contains become that row's keys.

Multi-row is confirmed by capture, not inferred. A ten-row `T100` read arrives as ten
`<item>` elements split across two `0x3c05` fragments of 9 and 773 bytes, the first
holding only the opening tag — so **fragment boundaries fall wherever the server
chooses, not on item boundaries**. Golden fixture:
`tests/golden/framing/basxml_et_data_multirow_response.bin`.

!!! warning "The XML form is not blank-padded"
    Unlike the binary encoding, the XML form does **not** pad fields to their DDIC
    width. The same query returns `ARBGB` as `FL` here and as `FL` followed by
    eighteen spaces through `DATA`. Row content is otherwise identical field for
    field, but a caller splitting the delimited row gets trimmed values on one path
    and padded values on the other. Verified by running the identical query with and
    without `USE_ET_DATA_4_RETURN`.

!!! danger "This is NOT SAP's BASXML"
    They share a TLV tag and nothing else. SAP's BASXML is a **binary tokenised**
    format: `BasXmlRenderer` writes a header beginning with the literal magic
    `BXML`, then token bytes and a string table, under the
    `http://www.sap.com/abapxml` namespace — an element open is the byte `0x3c`
    followed by a string-table index, not the character `<`. `BasXMLParser` reads it
    back with length-prefixed strings.

    That format is **not implemented**. A payload carrying the `BXML` magic is
    refused with `NotImplementedError` rather than fed to the text reader, which
    would silently produce nonsense.

### Compressed tables — CONFIRMED (2026-08-26)

A table larger than roughly 8 KB is sent SAPCOMPRESS-compressed under tag `0x0305`
instead of one `0x0303`/`0x0304` record per row. The switch happens when
`row_size × row_count >= 0x2001` (8193). This is not a rare path: it is every
function module with enough parameters, so `RFC_GET_FUNCTION_INTERFACE` metadata for
most BAPIs arrives compressed.

Golden fixture: `tests/golden/framing/gfi_compressed_params_response.bin` — the GFI
response for `BAPI_USER_GET_DETAIL` (44 parameters, 404 × 44 = 17776 bytes).

```
0x0301  len=12         table name "PARAMS" (UTF-16LE)
0x0330  len=4          DM table id
0x0302  len=8          [BE row_size=404][BE row_count=44]
0x0310  len=4          used row width (402) — the layout width without padding
0x0305  len=250        compressed fragment  } eight fragments of
0x0305  len=250        compressed fragment  } ONE stream, 2000 bytes joined
...
0x0306  len=0          table end
```

The `0x0305` records are **fragments of a single stream**, not independently
compressed blocks — decompressing one on its own fails. Concatenate them all first.
The joined payload then carries an 8-byte wrapper before the SAPCOMPRESS stream:

```
[0:4]   unidentified
[4:8]   BE uint32 — length of the compressed stream (1921 here)
[8:]    SAPCOMPRESS stream:
        [0:4] LE uint32 uncompressed length (17776)
        [4]   algorithm byte (0x12 → LZH)
        [5:7] magic 1f 9d
        [7]   config
```

Trailing bytes after the compressed stream pad the last record to its fixed size.

!!! warning "Two row shapes, two slicing rules"
    Per-row records and a compressed blob cannot be handled the same way.

    * **Per-row `0x0303`/`0x0304`** — each record is one row at its *used* width. The
      `0x0302` stride may be larger: a structure-definition response declared
      `row_size=140` while every record was 138 bytes.
    * **Compressed `0x0305`** — the decompressed blob carries no row boundaries, so
      it must be sliced by the `0x0302` stride.

    Slicing per-row records by the declared stride misaligns every row after the
    first; slicing a decompressed blob by the record length is impossible. The
    `0x0302` row size is authoritative only for the compressed form.

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

### Server registration (registered server → gateway)

Confirmed from live capture — golden fixture
`tests/golden/framing/server_registration_request.bin` (457 bytes including the NI header).

Parameter validation applied before the frame is built: PROGRAM_ID must be non-empty, at most
64 characters, and must not contain `*`; the gateway host string is capped at 2048 characters;
the gateway service must be non-empty. `saprfclib` enforces the same limits in
`server_session.py` so an invalid registration fails locally rather than at the gateway.

**Registration request (server → gateway)** — the same `0x0601` GW_CONNECT frame a client
emits, and independent of the PROGRAM_ID on the wire:

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
(`0x060F` data + `0x0605` GW_DONE) carrying the assigned handle and the peer IP. It is
deserialized by the same TLV path as a client-side response — the server direction is the
client direction run backwards, which is why `server_session.py` mirrors `session.py` rather
than reimplementing the parse.

All inbound bytes are peer-influenced and therefore untrusted: parse them with the
bounds-checked TLV walker, never with offset arithmetic that trusts a length field.

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
    0x0667  len=8          server call duration — float64 LE, microseconds
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

**Updated by live capture:** an early working assumption was "no CPIC header on the wire". That
was wrong. CPIC itself is a state machine and contributes no framing, but the **SAP Gateway
transport** (APPC layer) does add a 76-byte header to every RFC data frame on port 3300.

The correct picture:

```
Wire = NI(4B) + APPC_GW_HEADER(76B) + RFC_MARKER(4B) + TLV_STREAM
```

The CPIC-side conversions are internal data-format handling (8-bit byte representation ↔ CPIC
native format), not wire framing — they leave no trace in the bytes.

**Open question:** connecting directly to port 3200 (dispatcher rather than gateway) — does the
APPC header still appear? Not confirmed by capture. Port 3300 is the path every client tested
uses by default, so this has not been exercised.

---

## Python Reference Implementation

```python
import struct

NI_HEADER_SIZE = 4  # confirmed by every golden fixture

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

!!! note "RESOLVED: APPC/Gateway header (76 bytes) field layout"
    Fields [8-39] were decoded against the `gw_connect_response.bin` golden fixture. Key
    fields: [16] flags, [21] sub-type, [24-27] CPIC handle/sequence, [34] rc-valid flag,
    [36-39] CPIC return code, [40-43] additional status, [44-51] gateway handle.
    `saprfclib` consumes only [44-51]; everything else is CPIC internal state it does not
    need. Full layout in the "APPC/Gateway Header" section above.

!!! note "MEDIUM: Port 3200 (dispatcher) wire format"
    All captures used port 3300 (gateway). If a client connects directly to port 3200
    (dispatcher), does the APPC header still appear? Resolve by capturing both ports against
    the same system.

!!! note "LOW: COM_HEAD scope"
    COM_HEAD is confirmed present in the logon frame and absent from subsequent call frames.
    Not yet verified: whether it also appears on the first message of a tRFC/qRFC/bgRFC
    exchange, or is strictly session establishment.

!!! note "LOW: Classic RFC (non-NG) wire format"
    NG-RFC uses COM_HEAD + TLV. Classic CPI-C connections use a different format. Every system
    tested (NetWeaver 7.58) negotiates NG-RFC, so the classic format is undocumented here and
    unimplemented.

---

## Known Gaps

Items where the wire behaviour is documented but incompletely confirmed, or confirmed but not
yet implemented. Each states what is known, what is not, and the consequence of the gap.

### SAProuter NI_ROUTE prefix — CONFIRMED (2026-06-27)

Wire format confirmed from live capture: `NI_ROUTE\0` (9B) + talk_mode (`0x02`) + `0x28` +
version (`0x02`) + hop_count (4B BE) + total_data_length (4B BE) + per-hop entries
(entry_len [4B] + host`\0` + svc [6B]) + final destination (host`\0` + svc [6B]).
Golden fixture: `tests/golden/router/ni_route_payload.bin`. Implemented and replayed in CI.

### Message-server SAPMS group logon — CONFIRMED (2026-06-27)

The `**MESSAGE**` server-list frame is parsed by `parse_sapms_server_list` in
`src/saprfclib/router.py` and validated against `tests/golden/router/sapms_server_list.bin`
(598 bytes, 3 entries).

**SAPMS MESSAGE frame layout** (server-list response, wire-captured 2026-06-27):

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

**Entry count:** `N = (frame_size - 118) / 160`. No confirmed count field exists in the header
— the count is inferred from the remaining bytes. [ASSUMED] that a frame always contains whole
entries (`size % 160 == 0`).

**Server selection:** the first entry with `port > 0` is the active application server.
`sysnr = (port - 3200) // 100` (port 3200 → sysnr 0).

**Still [ASSUMED]:** `key` (offset 15), `msg_type` / `direction` (70/71), `opcode_field` /
`sub_opcode` (114/116), `field3` (80-120), `ip_addr_secondary` (141), `trailing_flags` (147),
and the inferred entry-count mechanism. None of these block correct server selection, which is
why they remain open.

### Function-interface metadata column layout — CONFIRMED (2026-06-27)

`RFC_GET_FUNCTION_INTERFACE` returns 12 columns: `PARAMCLASS, PARAMETER, TABNAME, FIELDNAME,
EXID, POSITION, OFFSET, INTLENGTH, DECIMALS, DEFAULT, PARAMTEXT, OPTIONAL`. `EXID` is a
single-character type code (`'C'` = CHAR, `'I'` = INT4, …); `INTLENGTH` and `OFFSET` are
Unicode byte counts, not character counts — the usual 2× trap. Parsed by `_parse_params_row`
in `metadata.py`, live-verified.

#### TABLES params: the direction types the parameter, not EXID — CONFIRMED

A TABLES parameter is declared with the `EXID` of its **row structure**, not of the table.
`RFC_READ_TABLE`'s `DATA`, `FIELDS` and `OPTIONS` all come back as `PARAMCLASS='T'` with
`EXID='u'` (structure) and `TABNAME` naming the row type (`TAB512`, `RFC_DB_FLD`,
`RFC_DB_OPT`). Typing the parameter from `EXID` alone therefore mistypes every TABLES param
as a bare structure.

`PARAMCLASS` is what decides. `'T'` means the wire carries a table, and
`tests/golden/framing/rfc_read_table_response.bin` shows it directly: all three params are
transported with the table tag sequence `0x0301 / 0x0330 / 0x0302 / 0x0304`, never as a
`0x0203` scalar value. `_parse_params_row` promotes `PARAMCLASS='T'` rows to `RFCTYPE_TABLE`
on that basis.

The promotion applies only to top-level rows (blank `FIELDNAME`). Nested rows describe fields
*inside* the row structure and repeat the parent's `PARAMCLASS`, so they keep their `EXID`
type.

Consequence of getting this wrong, both directions: the request emits the scalar
`0x0201`/`0x0203` pair and the server rejects the call with `CALL_FUNCTION_ILLEGAL_P_TYPE`;
the response decodes concatenated row bytes as a single work area, silently dropping every
row past the first.

A TABLES param also needs its row layout attached — the secondary
`RFC_GET_STRUCTURE_DEFINITION` lookup keyed on `TABNAME` runs for `RFCTYPE_TABLE` as well as
`RFCTYPE_STRUCTURE`, otherwise the descriptor reaches the encoder with `type_desc=None` and
no rows can be laid out.

#### Unset fields in a structure or table row

ABAP initialises a work area before an RFC fills it, so callers routinely supply only the
fields they care about — `RFC_READ_TABLE`'s `FIELDS` rows are the canonical case, where only
`FIELDNAME` is set. Fields absent from a row dict are encoded at their type's initial value
rather than skipped: fixed-width character fields must land blank-padded and numeric fields
zero-padded, so leaving the buffer's NUL fill in place would put the wrong bytes on the wire.

### Logon password scrambling (tag 0x0117) — CONFIRMED

Tag `0x0117` (17 bytes) is not a hash. It is a reversible byte cipher over the password:
`seed (4B LE) + scramble(password_bytes, seed)`. The seed is stored **little-endian**, not
big-endian. Implemented as `_scramble_password` in `src/saprfclib/connection.py` and verified
against a live logon. See [handshake.md](handshake.md) for the derivation.

!!! warning "This is obfuscation, not encryption"
    The scheme is reversible by anyone holding the frame. Passwords on a plain RFC connection
    are effectively in the clear on the network. Use SNC or WebSocket RFC over TLS for any
    connection that leaves a trusted segment.

### System-failure error detail — NOT IMPLEMENTED

`AbapSystemFailure` currently exposes only `message`. The full error-info field set
(return code, ABAP message class/type/number, message variables V1–V4, group, key) is not
parsed out of the response TLV, and the tags carrying it on a system failure have not been
identified in a capture. Consequence: less diagnostic detail on system failures than a C-SDK
client provides. Not a correctness problem for the returned data.

### Exception TLV semantics — the tag set varies by release

`0x0417` is the marker: its presence is what makes a response an exception rather than a
result (an exception response carries no `0x0420` at all). It holds the message number —
3 characters, e.g. `"000"`, `"341"`. The mapping to *exception key* and *message number*
was confirmed by matching a `RAISE EXAMPLE` in ABAP against the captured frame, and again
against `FU_NOT_FOUND` from `RFC_GET_FUNCTION_INTERFACE` for a non-remote-enabled module.

**The tag carrying the key is not the same on every release.** Kernel 793 puts it in
`0x0401`; a 7.52 system puts it in `0x0403` and adds the free message text in `0x0402`,
neither of which appears in any 793 capture. A reader that knows only the 793 tags gets
`key=None` and `message=None` from a 7.52 exception while the text sits unread in the
frame — this is exactly what happened before
`tests/golden/framing/signon_incomplete_752_response.bin` was captured. Both spellings are
now read, 793's first.

**The text encoding is not fixed either.** 793 sends these fields as UTF-16LE; the 7.52
capture sends them single-byte. The two are not distinguishable by "are all bytes < 0x80"
— ASCII text in UTF-16LE passes that test too and then decodes as `"L o g o n"` — so the
width is detected per value from the interleaved-NUL pattern rather than assumed from the
connection's Unicode flag.

Two `[ASSUMED]` labels remain in `invoke.py`, both waiting on a capture that happens
to contain the field. Neither affects correctness of the data an RFC call returns —
they can only make an error message less complete than it could be.

| Tag | Assumed to be | Why it is unconfirmed |
|-----|---------------|-----------------------|
| `0x0412`–`0x0414` | Message variables V2–V4 | Only V1 (`0x0411`) has ever appeared. The three are inferred from V1 being `0x0411` and the numbering running consecutively. A capture of a `MESSAGE ... WITH` raising four variables would settle it. |
| `0x040B` | Free-text exception message | Never observed in any capture. It predates the 7.52 work; `0x0402` is now the *confirmed* free-text tag, and the reader tries `0x040B` first only because removing an untested fallback is a change with no evidence behind it either. If a capture shows `0x040B` is something else, it should be dropped rather than relabelled. |

Also captured but not parsed: the grammar of the `0x0418` call-stack breadcrumb.

### Binary TABLE descriptor layout (0x0302 / 0x0330) — PARTIALLY CONFIRMED

Captures confirm `0x0330` (4 bytes, purpose unknown), `0x0302` (8 bytes, containing row count
and row width) and `0x0304` (fixed-width UTF-16LE row data). The exact byte positions of row
count and row width inside the 8-byte `0x0302` value are inferred from pattern-matching across
captures, not independently confirmed. Consequence: a wrong inference would produce a wrong row
count or misaligned rows on binary TABLE parsing — visible immediately rather than silently.

### Unsupplied optional CHANGING parameters — UNCONFIRMED

Supplied CHANGING parameters use `0x0201` + `0x0203`, same as IMPORTING — confirmed. Not
confirmed: whether an *unsupplied* optional CHANGING parameter should be omitted from the
request entirely or sent as a zero-value placeholder. `saprfclib` omits it, matching its policy
for IMPORTING and EXPORTING. If a given function module expects an explicit placeholder, the
call would fail at the ABAP layer rather than silently misbehave.

---

## Cross-References

- [Serialization](serialization.md) — ABAP type encoding inside TLV data payloads
- [Handshake](handshake.md) — logon handshake TLV sequence
- [Methodology](methodology.md) — how this documentation was derived and how to extend it

---

*Last updated: 2026-06-28.*
*Captures: SAP NetWeaver 7.58, sysnr=00, port=3300.*
