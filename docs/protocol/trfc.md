# tRFC / qRFC / bgRFC Wire Protocol

**Evidence:** tRFC and qRFC submit and confirm match the reference client byte for byte
(live captures 2026-11-12, golden fixture `tests/golden/trfc/trfc_reference.json`).
bgRFC submit is open — see [Known Gaps](#known-gaps).

---

## Overview

tRFC, qRFC and bgRFC are **not distinct wire frame types**. They are ordinary synchronous RFC
calls to SAP *system* function modules, discriminated by the **function name** in the standard
`0x0102` TLV tag — see [framing.md](framing.md) §"RFC Function Call Sequence". The call to run
travels serialized *inside* a table parameter of that system module.

```
tRFC / qRFC = 0x0504, then a call of ARFC_DEST_SHIP with TABLES STATE and DATA
              (the TID in STATE, the serialized calls in DATA)
            + later 0x0513, then a call of API_CLEAR_TID with parameter TID
bgRFC       = a call of BGRFC_DEST_SHIP (unit ID in SSTATE, calls in SDATA)
            + later a call of BGRFC_DEST_CONFIRM
```

If you are looking for a tRFC frame type in a capture, you will not find one — look for the
function name instead.

---

## Call-Type Discriminator

| Function name (`0x0102` TLV value) | Call type |
|------------------------------------|-----------|
| `ARFC_DEST_SHIP` | tRFC or qRFC submit |
| `API_CLEAR_TID` | tRFC / qRFC confirm (what the reference client sends) |
| `API_CREATE_TID` | a TID issued by the server (reference client, before the submit) |
| `ARFC_DEST_CONFIRM` | inbound only: read by the RFC server's dispatch **[ASSUMED]** |
| `BGRFC_DEST_SHIP` | bgRFC submit |
| `BGRFC_DEST_CONFIRM` | bgRFC confirm |
| `BGRFC_CHECK_UNIT_STATE_SERVER` | bgRFC state query |
| *(any other name)* | Ordinary synchronous RFC |

**tRFC vs qRFC:** both are `ARFC_DEST_SHIP`. A qRFC call carries its queue name in the STATE
row's `ARFCRESERV` column (below).

---

## tRFC Wire Format: ARFC_DEST_SHIP

Observed on 2026-11-12, reference client (pyrfc 3.3.1, NW RFC SDK 7.50) against an S/4HANA
system, kernel 793: a LUW of two `STFC_CONNECTION` calls, the same as qRFC, and an
`STFC_STRUCTURE` call with 12 table rows followed by `STFC_CONNECTION`. saprfclib's frames
for the same calls are byte-identical (`tests/test_trfc_submit.py`), and the server ran them
(`ARFCRSTATE` read back as `FINISHED`; `tests/test_phase06_integration.py`).

### Submit

```
0504                        empty, first record
0502 000b "754" 0102 "ARFC_DEST_SHIP" 0512
0205 "STATE"  0205 "DATA"   only these two are declared
0301 "STATE" 0330 1 0302 [width 972][rows]  0303 row ...   one row per call
0301 "DATA"  0330 2 0302 [width 1918][rows] 0303 row ...   the serialized calls
ffff
```

The row widths are the structures' widths from the server's metadata: `ARFCRSTATE` is 972
bytes and `ARFCRDATA` is 1918 — its last field ends at 1917 and the structure is padded to
its alignment (see [framing.md](framing.md), "Row width"). saprfclib takes both layouts from
`ARFC_DEST_SHIP`'s own metadata; nothing about them is hardcoded.

### STATE rows (ARFCRSTATE)

One row per call in the LUW. Unicode offsets:

| Column | Type | Offset | Value the reference client writes |
|--------|------|--------|-----------------------------------|
| `ARFCIPID` | CHAR 8 | 0 | TID characters 1-8 |
| `ARFCPID` | CHAR 4 | 16 | TID characters 9-12 |
| `ARFCTIME` | CHAR 8 | 24 | TID characters 13-20 |
| `ARFCTIDCNT` | CHAR 4 | 40 | TID characters 21-24 |
| `ARFCDEST` | CHAR 32 | 48 | `EXTERNAL` |
| `ARFCLUWCNT` | CHAR 8 | 112 | the call's position in the LUW, `00000001`, `00000002`, ... |
| `ARFCSTATE` | CHAR 8 | 128 | blank |
| `ARFCFNAM` | CHAR 30 | 144 | the function module |
| `ARFCRETURN` | CHAR 1 | 204 | blank |
| `ARFCUZEIT` | TIMS | 206 | `000000` |
| `ARFCDATUM` | DATS | 218 | `00000000` |
| `ARFCUSER` | CHAR 12 | 234 | blank |
| `ARFCRETRYS` | NUMC 4 | 258 | **blank**, not `0000` |
| `ARFCTCODE` | CHAR 20 | 266 | blank |
| `ARFCRHOST` | CHAR 8 | 306 | the client host name, cut to 8 characters |
| `ARFCMSG` | CHAR 50 | 322 | blank |
| `ARFCRESERV` | CHAR 255 | 422 | the program name; for qRFC `I` + queue name from character 44 |
| `HASH` | RAW 40 | 932 | zeros |

### DATA rows (ARFCRDATA)

Each call is serialized as a TLV stream (below), and the bytes are cut into consecutive
pieces of 1785 bytes — the seven 255-byte `ARFCDATA01`..`ARFCDATA07` columns. Each piece is
one row; the last is zero-padded. A row starts with the same key as its STATE row
(`ARFCIPID` .. `ARFCLUWCNT`), then `ARFCBLCNT`, RAW 4, the piece number from 1, big-endian.
The `STFC_STRUCTURE` call above, 3839 bytes serialized, took three rows (1785 + 1785 + 269).

### A serialized call

```
0101 03 01 01 05 04 01 00 03   0103 00 00 0e 09   0106 04 01 00 03 00 0a 02 00 00 00 23
0514 session token             (as in the logon)
0007 client address            (the logon's 0x0007, UTF-16LE here)
0011 language                  (the logon's 0x0011)
0012 "754"                     (the logon's 0x0012)
0013 kernel + address          (the logon reply's 0x0013, "793 ", then its 0x0018)
0008 client host               (the logon's 0x0008)
0006 server host               (the logon reply's 0x0006)
0130 program                   (the logon's 0x0130)
0502 000b "754" 0102 <function>
0201/0203 ..., 0301/0302/0303 ...   the parameters, as in an ordinary call
ffff                           the stream ends FF FF 00 00 FF FF
```

The call part differs from an ordinary call in three ways: no `0x0512`, no `0x0205`
declarations (nothing comes back) and no `0x0330` table ids. The same header precedes the
calls inside a bgRFC unit's `SDATA` (below), from a separate capture.

### Confirm

```
0513   empty, first record
0502 000b "754" 0102 "API_CLEAR_TID" 0512 0201 "TID" 0203 <TID, 24 characters> ffff
```

After the confirm the server deletes the TID from `ARFCRSTATE` (read back live). Before it,
a resubmit of the same TID is answered without error and does not add a second entry.

### The 24-character TID

The TID is a 24-character string travelling in the first four STATE columns. TIDs issued by
the server (`API_CREATE_TID`, which the reference client calls before a submit) are
**uppercase hexadecimal**: IP address, process ID, time and counter, e.g.
`C6336407C2106AF58D710000` (`C6336407` = 198.51.100.7, documentation address).

`create_tid()` makes the TID locally: `uuid4().hex[:24].upper()`, 24 uppercase hex
characters. A live server accepts such TIDs and runs the call under them (2026-11-12).
saprfclib also accepts `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-` **[ASSUMED]**: the
characters beyond hex were not probed.

---

## qRFC: the queue name

qRFC is tRFC with a queue name in `ARFCRESERV`: the program name, padded to 44 characters,
then `I`, then the queue name (fixture `qrfc` section). The server writes the call into its
inbound queue table `TRFCQIN` under that name (read back live). Whether the queue is then
processed depends on the system's queue registration (`SMQR`).

Queue names are 1 to 24 characters: `TRFCQIN-QNAME` is CHAR 24, and a 25-character name was
accepted and **silently cut** to 24 (probe 2026-11-12). saprfclib refuses longer names.

---

## bgRFC Wire Format: BGRFC_DEST_SHIP

bgRFC uses its own function module, `BGRFC_DEST_SHIP`:

Read from the dictionary on A4H kernel 793 (2026-09-04) via
`RFC_GET_FUNCTION_INTERFACE`, so these are the module's declared parameters, not
an inference. Widths are Unicode (`uc_length`); halve for the non-Unicode column.

| ABAP parameter | Dir | Type | Notes |
|----------------|-----|------|-------|
| `OUT_IN_QUEUE_NAME_TAB` | IMPORT | TABLE | rows of `QRFC_QUEUE_NAME_TAB`, one CHAR(40) field |
| `SDATA` | IMPORT | XSTRING | serialized payload — the calls buffered in the unit |
| `SSTATE` | IMPORT | STRUCTURE | `BGRFC_SRV_STATE`, 616 bytes — **carries the unit ID** |
| `SUPPORTABILITY_INFO` | IMPORT | STRUCTURE | `BGRFC_SUPPORTABILITY_INFO`, 112 bytes |
| `SHUTDOWN_ACTIVE` | CHANGING | CHAR(1) | |
| `BGRFC_RETRY_DELAY_TIME` | EXPORT | INT4 | retry delay, seconds |
| `BGRFC_RETRY_KEY` | EXPORT | CHAR(24) | |
| `BGRFC_RETRY_MAX_COUNT` | EXPORT | INT4 | |
| `SERVER_STATE` | EXPORT | INT4 | |
| `SHUTDOWN_INSTANCE` | EXPORT | CHAR(40) | |

**There is no `BGRFC_UNIT_ID` parameter, and no `BGRFC_UNIT_TYPE`.** The unit ID
is the first field of the `SSTATE` structure:

| `BGRFC_SRV_STATE` field | Type | uc_offset | uc_length |
|--------------------------|------|-----------|-----------|
| `UNIT_ID` | BYTE | 0 | 16 |
| `UNIT_KIND` | INT4 | 16 | 4 |
| `DESTINATION` | CHAR(32) | 20 | 64 |
| `QUEUE_NAME` | CHAR(40) | 84 | 80 |
| `STATE` | INT4 | 164 | 4 |
| `UNIT_SIZE` | INT4 | 168 | 4 |

`BGRFC_SUPPORTABILITY_INFO` repeats `UNIT_ID` BYTE(16) at offset 0 and
`UNIT_KIND` INT4 at offset 96.

Two consequences for anything building this frame:

* The unit ID travels as **16 raw bytes**, not as its 32-character hex rendering,
  and not in UTF-16LE. The hex form is a display convention.
* `UNIT_KIND` is an **INT4**. The `'T'`/`'Q'` characters below are an API
  convention; the wire carries the integers in "What a reference client actually
  sends" below (`1409196105` for a type `T` unit). The value for `'Q'` is
  **[ASSUMED]** (`1409196101`, by symmetry; `invoke.py`).

### The two simple modules

`BGRFC_DEST_CONFIRM` and `BGRFC_CHECK_UNIT_STATE_SERVER` take the unit ID
directly rather than through a structure:

| Module | IMPORT | EXPORT |
|--------|--------|--------|
| `BGRFC_DEST_CONFIRM` | `UNIT_ID` BYTE(16), `UNIT_KIND` INT4, five optional `RS_*` | `RS_SERVER_RESOURCES_RC` INT4, `RS_SYSTEM_IDENTITY` |
| `BGRFC_CHECK_UNIT_STATE_SERVER` | `UNIT_ID` BYTE(16), `UNIT_KIND` INT4 | `STATE` INT4, `INSTANCE_NAME`, `MAX_WPRUN_TIME`, `COMMUNICATION_FAILURE`, `SYSTEM_FAILURE` |
| `BGRFC_GET_UNIT_ID` | — | `UNIT_ID` BYTE(16) |

Both are ordinary signatures the dictionary describes, so neither needs a bespoke
TLV builder — the normal invoke path encodes them. `BGRFC_GET_UNIT_ID` works and
returns a 16-byte ID; saprfclib does not use it (see below).

### The 32-character UnitID

A UnitID is **32 uppercase hex characters** — a UUID with the dashes removed.

saprfclib always generates it locally (`uuid4().hex.upper()` in `create_unit`). The
reference client takes it from `BGRFC_GET_UNIT_ID` instead.

Example: `A1B2C3D4E5F6789012345678901234AB`

### Unit type character

| Character | Meaning |
|-----------|---------|
| `'T'` (0x54) | No queue names — synchronous execution |
| `'Q'` (0x51) | One or more queue names specified |

The rule is "queue count < 1 → `'T'`, otherwise `'Q'`". The wire carries the matching
`UNIT_KIND` integer; a wrong one is **not** reported — the unit then reads as `NOT_FOUND`
(see "What a reference client actually sends").

---

## Client-Side Orchestration

### tRFC / qRFC submit and confirm

```
conn.call_transactional("FM", tid=tid, queue=None, **params)
    │
    ├─ 1. metadata of FM and of ARFC_DEST_SHIP (cached)
    ├─ 2. serialize the call: header from the logon + build_invoke_request(transactional=True)
    ├─ 3. build_trfc_request: STATE row (TID, FM, queue), DATA rows (the serialized call)
    ├─ 4. send, read the reply; an error raises
    └─ retried on CommunicationError with the same TID (the server runs it once)

conn.confirm_tid(tid)
    └─ API_CLEAR_TID with the TID -- the server forgets it
```

One call per TID: the reference client can put several calls into one LUW, the public API
sends one.

### bgRFC submit and confirm

```
with conn.create_unit(uid, queues=["Q1"]) as unit:
    unit.call("FM1", ...)   # buffered, not sent yet
    unit.call("FM2", ...)   # buffered
# __exit__ → build_bgrfc_request → BGRFC_DEST_SHIP. It still sends BGRFC_UNIT_ID /
#   BGRFC_UNIT_TYPE / BGRFC_QUEUE_n / BGRFC_CALL_COUNT, which the module does not declare:
#   the submit does not work (issue #34).

conn.confirm_unit(identifier)
    └─ build_invoke_request("BGRFC_DEST_CONFIRM", ...)

conn.get_unit_state(identifier)
    └─ build_invoke_request("BGRFC_CHECK_UNIT_STATE_SERVER", ...)
```

---

## Server-Side Dispatch

When a registered RFC server receives an inbound call, the function name is matched before the
normal handler lookup. **[ASSUMED]**: the server takes the TID from a parameter named
`ARFCTID` and, failing that, from the 8 + 4 + 8 + 4 characters of the inbound `0x5001`
block; neither is the client format above. No capture of a SAP system sending tRFC to a
registered server exists to settle what arrives.

```
inbound frame
  → decode function name from TLV 0x0102
       │
       ├─ "ARFC_DEST_SHIP"     → read the TID (see above)
       │                         → on_check(tid), or the TID store
       │                              16 (executed) → skip the handler, report success
       │                              0 (new)       → mark received, run the handler
       │
       ├─ "ARFC_DEST_CONFIRM"  → placeholder: answers OK and does nothing
       ├─ "BGRFC_DEST_SHIP"    → [ASSUMED] reads BGRFC_UNIT_ID / BGRFC_UNIT_TYPE / BGRFC_CALL_n,
       │                         which only saprfclib's own builder writes; checks the unit,
       │                         then plays it back
       └─ *(else)*             → ordinary handler dispatch
```

### on_check callback contract

`install_transaction_handlers(on_check=...)`:

| Return | Meaning |
|--------|---------|
| 16 (`RFC_EXECUTED`) | TID already known and executed → skip the handler, return success |
| 0 (`RFC_OK`) | New TID → persist it and execute |

The reply's return code is 0 for success, 16 for an executed TID and 3 for a failure; 16 and
3 are **[ASSUMED]** (`server.py`, `_RC_EXECUTED`).

### Callback order

```
on_check(tid)                     → 16? → skip
mark_received(tid) BEFORE execute ← crash safety: persist before you run
run_handler()
  ├─ success → mark_executed(tid); on_commit(tid)   (on_confirm only on a confirm)
  └─ error   → on_rollback(tid)
```

`mark_received` **before** execution is what makes exactly-once survive a crash mid-handler. If
you persist afterwards, a process death between execution and persistence replays the LUW.

---

## TID / UnitID Validation

Inbound TID and UnitID values arrive as ABAP CHAR fields inside function parameters. They are
attacker-influenced input and become store keys, so validate before use:

| Field | Length | Valid charset | Action on invalid |
|-------|--------|---------------|-------------------|
| TID | exactly 24 characters | `A-Z0-9/_=@-` | Reject with a system failure (return code 3) |
| UnitID | exactly 32 characters | `0-9A-F` (uppercase hex) | Reject |

The client validates queue names (1–24 characters) before sending; the server does not see
them in its current inbound path.

---

## Pitfalls

### 1. Treating tRFC as a distinct frame type
It is a synchronous call to `ARFC_DEST_SHIP`, with the call to run serialized inside its
`DATA` table. There are no `ARFCTID` / `ARFCFNAM` / `ARFCQUEUE` parameters: the module
declares none of them, and a server answers "Field TID did not have a value" (issue #36).

### 2. Wrong TID character set
TIDs seen live are 24 uppercase hex characters. saprfclib also accepts
`ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-` **[ASSUMED]**; stay with hex to be safe.

### 3. Confirming before success
`confirm_tid()` removes the backend's duplicate protection. Calling it before you have verified
the call landed defeats exactly-once. Submit and confirm are deliberately separate calls —
keep them that way.

### 4. Off-by-2× on TID / UnitID byte length
TID = 24 characters × 2 bytes = 48 bytes UTF-16LE. The UnitID travels as its **16 raw
bytes**, not as the 32-character hex text. All character length arithmetic is in code
units, not Python `len()`.

### 5. bgRFC unit type `'T'` vs `'Q'`
The `UNIT_KIND` sent must match the queue list: the type `'T'` value when `queues=[]`, the
`'Q'` value when queues are given. A mismatch is not reported; the unit reads as `NOT_FOUND`.

### 6. Looking for a call-type byte
The discriminator is the **function name string** in TLV `0x0102`, not a separate byte. Branch
on the decoded function name before the normal handler lookup.

---

## Known Gaps

### Inbound tRFC (SAP to a registered server)
A capture on 2026-07-05 of a tRFC the SAP system sent to a registered server showed a
compact block encoding: CHAR values as `0x43 [len] 0x80 [value]`, the TID fields at offsets
504 / 515 / 522 / 533 as 8 + 4 + 8 + 4 uppercase hex characters, `ARFCFNAM` at 1716, and an
unexplained 11-byte preamble `34 08 0c 00 00 4c 07 00 00 f1 31` at offset 14. The server's
inbound handler does not parse it yet ([ASSUMED] in `server.py`).

### Several calls in one LUW (not in the public API)

The wire format carries any number of calls (fixture `trfc`: two). `call_transactional`
sends one per TID.

### tRFC over WebSocket RFC
No capture. `call_transactional` raises `NotImplementedError` on a WebSocket connection.

### BGRFC_DEST_SHIP payload byte layout
The live bgRFC test submitted a unit with empty parameters, so no payload bytes were captured
for bgRFC function parameters. **Consequence:** the bgRFC payload encoding is inferred from the
tRFC path rather than confirmed. **To close:** capture a bgRFC unit carrying real parameters.

What is now established, by submitting against a live system (A4H kernel 793, 2026-09-04):

* **`SSTATE` reaches the module intact.** An earlier submit answered "BGRFC_DEST_SHIP
  called without unit ID"; filling `SSTATE.UNIT_ID` with the 16 raw bytes clears that
  check, so the structure encoding itself works.
* **The module executes the unit inline.** It is not a queue insert followed by
  asynchronous execution — the submit deserializes `SDATA` and runs the calls in it
  before returning, then updates the state row to "finished".
* **Therefore `SDATA` cannot be isolated from `SSTATE`.** Submitting with an empty
  payload to test the state record alone does not work: the empty xstring still goes
  to the deserializer, which fails an assertion. Every attempt with an empty `SDATA`
  ends in `ASSERTION_FAILED`, whichever `UNIT_KIND` is used and whether or not the
  optional `SUPPORTABILITY_INFO` is supplied.

So the remaining unknown is the whole of it: `SDATA` is a serialized container holding
the buffered calls, and nothing can be submitted until its format is known. It is not
what this library buffers today (per call, the function name in UTF-16LE and its
`name=value` pairs joined by NUL characters).

That capture has now been taken (SDK trace, A4H kernel 793, 2026-09-07: one type `T`
unit carrying a single `STFC_CONNECTION` call with a marker string in `REQUTEXT`). The
traces are not committed as fixtures; the values below and the `SDATA` layout come from
them.

### What a reference client actually sends

| `SSTATE` field | Value observed | Note |
|----------------|----------------|------|
| `UNIT_ID` | 16 raw bytes | as issued by `BGRFC_GET_UNIT_ID` |
| `UNIT_KIND` | `1409196105` | tRFC **outbound**, for a type `T` unit |
| `DESTINATION` | the client's own hostname | *not* the inbound destination name |
| `CALLER_CLIENT` | `"000"` | not the logon client |
| `CALLER_USER` | the OS user | not the SAP user |
| `CALLER_TCODE` | `"NW RFC Library 754"` | the library identifies itself here |
| `CALLER_PROGRAM` | the executable name | |
| `SENDING_TIME` | BCD `20260807082915` | as captured; a month before the trace date, unexplained |
| `SENDING_INSTANCE` | the client hostname | |

`UNIT_KIND` is the trap. An external client sends the **outbound** value even though the
unit is going into the system, and a wrong choice is not reported: the state module
accepts all four values and selects on `(unit_id, unit_kind)`, so the wrong kind makes a
real unit read as `NOT_FOUND` — indistinguishable from one that was never submitted.

### `SDATA` container

    offset  size  content
    0       8     FF 06 02 01 02 02 80 00      fixed header [ASSUMED constant]
    8       4     "4103"                       codepage, single-byte ASCII
    12      4     00 00 00 00
    16      4     uncompressed length, LE uint32
    20      1     0x12                         SAPCOMPRESS algorithm = LZH
    21      ...   LZH-compressed payload

The compressed block is ordinary SAPCOMPRESS: `sapcompress_decompress()` in `compress.py`
decodes the captured payload exactly (410 bytes in, 1071 out). Inside is an RFC-recorder
serialization — it opens with a `SER_UNIT_TAB` name, carries the called function name as
`STFC_CONNECTION` blank-padded to 30 characters in UTF-16LE, a `basxml=0,` option string,
and the call's parameter values.

### Inside the compressed payload

The plaintext is not a new format. Decoding the captured 1071 bytes by hand gives an
ordinary RFC TLV stream — the same tags this library already builds — preceded by a
logon-style preamble:

    0514  16   session token
    0007  18   client IP address, UTF-16LE
    0011   2   logon language, "E"
    0012   6   release, "754"
    0013  32   kernel release and server address
    0008  10   client hostname
    0006  18   partner hostname
    0130  26   caller program name
    0502   0   request marker
    000b   6   release, "754"
    0102  30   function name, blank-padded to 30 characters
    0201  16   parameter name, "REQUTEXT"
    0203 510   parameter value, blank-padded to 255 characters

Everything from `0502` onward is byte-for-byte what `build_invoke_request` emits for the
same call. Ahead of the preamble sits an index section naming `SER_UNIT_TAB`, the called
function blank-padded to 30 characters, and an option string `basxml=0,`.

### The index section, by difference

Three captures differing in one way each — one call, two calls, one call to a shorter
function — separate the constants from the fields. What holds across all three:

| Offset | Width | Meaning | Evidence |
|--------|-------|---------|----------|
| `0x09` | BE uint16 | total plaintext length − 120 | 951/1892/399 against totals 1071/2012/519 |
| `0x7f` | uint8 | number of calls in the unit | 1 / 2 / 1 |
| `0x85` | 60 bytes | function name, UTF-16LE, blank-padded to 30 chars | changes only with the function |
| `0xc3` | 18 bytes | option string `basxml=0,` | constant across all three |
| `0xfa` | BE uint16 | length of the first call record, which starts at `0x100` | 815/815/263; `256 + 815 = 1071` and `256 + 263 = 519` |

The unit is a chain: the first call record runs from `0x100` for its declared length, and a
second call follows immediately after it. In the two-call capture the first record ends at
1071 — exactly where the second begins — and the second runs to 2012. Each record carries
its own copy of the function name and its own invoke TLV stream (`0502` at 469 in the
first record of every capture).

**Still open:** the descriptor grammar between `0x20` and `0x100`. It is a tagged
structure — a `SER_UNIT_TAB` name, then records shaped `<tag> <id> 00 00 00 00 <size>`
with tags `0xaa`, `0xad`, `0xae`, `0xaf`, and two-byte tags around `0xbc`/`0xbd`/`0xbe` —
but which of those are field descriptors of the container and which are values is not
established, and the second call record uses a shorter prefix than the first. Building a
submit needs that grammar; reading one does not.

### Compression

`sapcompress_compress_lzc()` encodes the LZC variant, round-tripping the captured payload
and every code width. The reference client uses **LZH**, and whether a server accepts LZC
in its place is untested — a submit is the only way to find out, and that is blocked on
the descriptor grammar above.

### Backend tables (A4H, kernel 793, observed 2026-09-04)

Which tables hold what, read off a live system rather than inferred from their names. This
matters because the obvious guess is wrong in a way that fails silently:

| Table | Holds |
|-------|-------|
| `BGRFC_CUST_SUPER` | supervisor destination — bgRFC does not run without one |
| `BGRFC_MAIN_I_DST` | inbound destination definitions (name + RFC server group) |
| `BGRFC_REG_I_DEST` | inbound queue-prefix registration |
| `BGRFC_SRV_STATE` | live unit state: `UNIT_ID, UNIT_KIND, DESTINATION, QUEUE_NAME, STATE, ...` |
| `BGRFC_IUNIT_HIST` | inbound unit history, written once a unit leaves `BGRFC_SRV_STATE` |
| `BGRFC_CUST_I_SRV` | **scheduler tuning per app server** — *not* a destination definition |
| `BGRFC_CUST_I_DST` / `BGRFC_CUST_O_DST` | **scheduler tuning per destination** — *not* definitions |

The last two rows are the trap. `BGRFC_CUST_I_SRV` and `BGRFC_CUST_I_DST` read like "inbound
server" and "inbound destination", and both stay **empty on a correctly configured system** —
they only fill in if someone tunes the scheduler. A configuration check that reads them reports
"bgRFC is not configured" for a system with both a supervisor and an inbound destination
defined, which is exactly what happened here before the tables were enumerated.

`BGRFC_SRV_STATE` is what makes issue #15 answerable at all: it lets a confirm be verified
against the backend's own record instead of against `get_unit_state()`, the function being
tested. Checking a decoder with itself cannot detect a decoding fault.

### ARFC_EXECUTE / ARFC_RUN_NOWAIT
Whether either is ever called separately from `ARFC_DEST_SHIP` is unconfirmed. Only
`ARFC_DEST_SHIP` has been observed in dispatch, and no `ARFC_EXECUTE` frame has appeared in any
capture.

---

*See also: [Framing](framing.md) and [Handshake](handshake.md) for the framing and logon layers.*
