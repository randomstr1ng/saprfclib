# tRFC / qRFC / bgRFC Wire Protocol

**Status:** BN-CONFIRMED — Binary Ninja decompilation of `libsapnwrfc.so.bndb` (2026-07-03).
**Gate D-09 status:** CLOSED — BN decompilation completed; live capture pending (synthetic fixture recorded below).
**Confidence:** HIGH for function-name discriminator and structural format; MEDIUM for exact byte-level
encoding of per-field TLV tags (live capture open gap — see §"Open Gaps").

---

## Overview

tRFC / qRFC and bgRFC are **not distinct wire frame types**. They are ordinary synchronous RFC
function calls to SAP *system* function modules. The call-type is discriminated by the **function
name** carried in the standard 0x0102 TLV tag (see `framing.md §"RFC Function Call Sequence"`).
The standard `build_invoke_request()` / `dispatch_inbound()` paths are reused unchanged for the
payload; Phase 6 adds the system-FM orchestration on top.

```
tRFC / qRFC = synchronous RFC invoke of ARFC_DEST_SHIP  (carrying TID in ARFCTID param)
            + optional later invoke of ARFC_DEST_CONFIRM
bgRFC       = synchronous RFC invoke of BGRFC_DEST_SHIP (carrying UnitID in BGRFC_UNIT_ID param)
            + optional later invoke of BGRFC_DEST_CONFIRM
```

**BN source:** `RfcServer::dispatch` at 0x4bb5de — the function name string (from TLV 0x0102) is
compared against `ARFC_DEST_SHIP`, `ARFC_DEST_CONFIRM`, `API_CLEAR_TID`, `BGRFC_DEST_SHIP`,
`BGRFC_DEST_CONFIRM`, `BGRFC_CHECK_UNIT_STATE_SERVER` before the normal handler lookup. This
string comparison IS the call-type discriminator.

---

## Call-Type Discriminator

The discriminator is the **function name TLV (tag 0x0102, UTF-16LE)** in the inbound RFC
invoke frame. The server reads it via the standard `_read_func_name()` path (Phase 5
`dispatch_inbound` at `server.py:391` — the Pitfall 6 seam) and branches based on the value:

| Function Name (0x0102 TLV value) | Call Type | BN Source |
|----------------------------------|-----------|-----------|
| `ARFC_DEST_SHIP` | tRFC (or qRFC — see §"qRFC") | `RfcServer::dispatch` 0x4bb5de, strcmpU16 at 0x4bb632 |
| `ARFC_DEST_CONFIRM` | tRFC confirm | `RfcServer::dispatch` 0x4bb5de, strcmpU16 at 0x4bb65a |
| `API_CLEAR_TID` | Internal TID clear | `RfcServer::dispatch` 0x4bb5de, strcmpU16 at 0x4bb697 |
| `BGRFC_DEST_SHIP` | bgRFC submit | `RfcServer::dispatch` 0x4bb5de, strcmpU16 at 0x4bb6b1 |
| `BGRFC_DEST_CONFIRM` | bgRFC confirm | `RfcServer::dispatch` 0x4bb5de, strcmpU16 at 0x4bb713 |
| `BGRFC_CHECK_UNIT_STATE_SERVER` | bgRFC state query | `RfcServer::dispatch` 0x4bb5de, strcmpU16 at 0x4bb733 |
| *(any other name)* | Synchronous RFC | Normal handler lookup |

**Implementation note:** The check for `*(r13_1 + 0xe58).b == 0` at 0x4bb632 distinguishes
tRFC from qRFC — when the queue-name byte at the ARFCSSTATE param table offset 0xe58 is non-zero,
the call is qRFC (queued). This byte is populated from the queue-name field carried as a row in
the ARFCSSTATE table parameter (see §"qRFC Queue Name" below).

---

## tRFC Wire Format: ARFC_DEST_SHIP

A tRFC submit is a standard synchronous RFC call to `ARFC_DEST_SHIP`. The wire frame is an
ordinary invoke frame as defined in `framing.md`, with function name `ARFC_DEST_SHIP` in TLV
0x0102 and the following ABAP parameters:

### ARFC_DEST_SHIP Function Parameters (BN 0x4b681e — getArfcDestShipFunctionDesc)

The function descriptor is built at `getArfcDestShipFunctionDesc()` (BN 0x4b681e). It creates
two tables: `ARFCSSTATE` (the control record, one row) and `ARFCSDATA` (payload rows,
one per ABAP function module invoked). The relevant fields from the ARFCSSTATE structure:

| ABAP Field Name | Type | NUC size | UC size | NUC Offset | Notes |
|-----------------|------|----------|---------|------------|-------|
| `ARFCIPID` | CHAR | 8 | 16B | 0 | IP identifier (host part of TID) |
| `ARFCPID` | INT4 | 4 | 8B | 8 | PID (process part of TID) |
| `ARFCTIME` | INT8 | 8 | 16B | 0x0c | Timestamp (time part of TID) |
| `ARFCTIDCNT` | INT4 | 4 | 8B | 0x14 | Counter (uniqueness part of TID) |
| `ARFCDEST` | CHAR | 32 | 64B | 0x18 | Destination name |
| `ARFCLUWCNT` | INT8 | 8 | 16B | 0x38 | LUW count |
| `ARFCSTATE` | CHAR | 8 | 16B | 0x40 | State |
| `ARFCFNAM` | CHAR | 30 | 60B | 0x48 | Function module name |
| `ARFCRETURN` | CHAR | 1 | 2B | 0x66 | Return code |
| `ARFCUZEIT` | TIME | 6 | 12B | 0x67 | Time |
| `ARFCDATUM` | DATE | 8 | 16B | 0x6d | Date |
| `ARFCUSER` | CHAR | 12 | 24B | 0x75 | User name |
| `ARFCRETRYS` | INT4 | 4 | 8B | 0x81 | Retry count |
| `ARFCTCODE` | CHAR | 20 | 40B | 0x85 | Transaction code |
| `ARFCRHOST` | CHAR | 8 | 16B | 0x99 | Remote host |
| `ARFCMSG` | CHAR | 50 | 100B | 0xa1 | Message |
| `RESERV` | BYTE | 255 | 510B | 0xd3 | Reserved |
| `HASH` | XSTRING | 40 | 40B | 0x1d2 | Hash |

**Source:** `getArfcDestShipFunctionDesc()` BN 0x4b681e → `RfcRecordMetaData_add` calls with
field names and offsets as documented above.

### The 24-Character TID Format

The TID is a 24-character string encoded in a **non-hexadecimal character set**.

**BN source:** `RfcTransaction::createTid(char16_t*)` at 0x4b5962 — local generation
(called when connection handle is NULL):

```c
// BN HLIL 0x4b5a33 — confirmed character table
char16_t alphabet[] = u"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-";  // 41 chars
// Each 4-byte input word is divided by 41 (modulo) to select a character
// Written to TID[j] for j in range(5, -1, -1) then 6 positions at a time
// Total: 24 characters (RFC_TID_LN = 24, sapnwrfc.h:79)
```

**Encoding algorithm (BN confirmed at 0x4b5a19–0x4b5a53):**
1. `own_ip`: 4 bytes of local IP address (init-once static, from `CpicConnection::getOwnIPNodeAddr()` at 0x4b598a)
2. `pid`: process ID (4 bytes, init-once static, `getpid()` at 0x4b59cc)
3. `time`: `time(nullptr)` — Unix seconds, 4 bytes (0x4b5a01)
4. `tidCount`: atomic counter, incremented via `ThrVarIncrement` (0x4b5a19)

Combined as a 16-byte struct (4×4B): each 4-byte word is converted to 6 characters via
modulo-41 into the `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-` alphabet → total 4×6 = 24 chars.

**Character set (BN 0x4b5a33):** `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-` (41 chars, uppercase)

**Wire encoding:** As an ABAP CHAR parameter (UTF-16LE) within the ARFCIPID/PID/TIME/TIDCNT
structure fields of the ARFCSSTATE table row inside the `ARFC_DEST_SHIP` invoke frame. The
24-char string returned by `RfcGetTransactionID` is the concatenation of the decoded characters
from these four fields; it is NOT sent as a standalone TLV tag.

**Key insight:** A TID generated by `uuid4().hex[:24].upper()` would use the HEX character set
(`0-9A-F`), which is a strict subset of the TID alphabet (`A-Z0-9/_=@-`). SAP accepts any
string in this alphabet (range check only), so a UUID-derived TID is valid on the wire, but
the authentic SDK format is the IP+PID+time+counter encoding above.

---

## qRFC: Queue-Name Discrimination

qRFC = tRFC + a queue name. On the wire, qRFC is sent via the **same `ARFC_DEST_SHIP`** function
module as tRFC. The queue name is passed in the `ARFCSSTATE` table parameter.

**BN source at 0x4bb632:** `strcmpU16("ARFC_DEST_SHIP", fname) == 0` AND
`r13_1[0xe58].b != 0` → qRFC branch. The byte at offset 0xe58 within the connection's
ARFCSSTATE table is the queue-name indicator. When non-zero, a queue name is present
and the call is treated as qRFC (queued RFC).

**Queue name bounds (sapnwrfc.h:365):** up to `RFC_MAX_QUEUE_NAME_LENGTH` characters; per
`RFC_UNIT_IDENTIFIER` the queue list is a `SAP_UC** queueNames` with `queueNamesCount`.

---

## bgRFC Wire Format: BGRFC_DEST_SHIP

bgRFC uses a separate function `BGRFC_DEST_SHIP` (confirmed at 0x4bb6b1). Its function
descriptor is built by `BgRfcUnit::getBgrfcDestShipFuncMeta()` (BN 0x50b846):

### BGRFC_DEST_SHIP Parameters (BN 0x50b846)

| ABAP Param Name | Type | Notes |
|-----------------|------|-------|
| `OUT_IN_QUEUE_NAME_TAB` | TABLE | QRFC_QUEUE_NAME_TAB structure; queue name(s) for this unit |
| `ARFCSDATA` | XSTRING | Serialized payload (function calls buffered in unit) |
| `ARFCSTATE` (= BGRFC_SRV_STATE) | STRUCTURE | State record (per BGRFC_SRV_STATE type) |
| `SUPPORTABILITY_INFO` | STRUCTURE | BGRFC_SUPPORTABILITY_INFO |
| `BGRFC_RETRY_DELAY_TIME` | INT4 | Retry delay seconds |
| `BGRFC_RETRY_KEY` | CHAR | Retry key (24 chars) |
| `BGRFC_RETRY_MAX_COUNT` | INT4 | Max retry count |
| `SERVER_STATE` (= BGRFC_EXE_STATE) | INT4 | Execution state indicator |

**UnitID carried as:** The 32-char UnitID is sent in the `BGRFC_UNIT_ID` field (or as part of
the state record / header). Generated by `BgRfcUnit::createUnitId()` (BN 0x511554) via
`pfcreate_sap_uuid()` → `pfuuid_print()` → 32 uppercase hex chars (UUID without dashes).

### The 32-Character UnitID Format

**BN source:** `BgRfcUnit::createUnitId` at 0x511554:
- When connection handle is non-NULL: calls `getBgrfcGetUnitIdFuncMeta()` → makes a server
  round-trip to `BGRFC_GET_UNIT_ID` → receives a 16-byte UUID → `pfuuid_print()` formats
  it as 32 uppercase hex characters (verified at 0x511855: `pfuuid_print(&var_50, uid_out, &len)`,
  then asserts `len == 0x20 = 32`).
- When connection handle is NULL (`RfcGetUnitID` with null handle): calls `pfcreate_sap_uuid()`
  locally → same `pfuuid_print()` path → 32 uppercase hex chars.

**Wire format:** `RFC_UNITID_LN = 32` characters (sapnwrfc.h:80), uppercase hex, no dashes.
Example: `A1B2C3D4E5F6789012345678901234AB`

**Unit type character (sapnwrfc.h:316, BN 0x483919):**
- `'T'` (0x54): no queue names (synchronous execution)
- `'Q'` (0x51): one or more queue names specified

**BN confirmation at 0x483919:**
```c
// sbb-based conditional: (queue_count < 1) ? 'T' : 'Q'
// 0x51 = 'Q'; when no queues: sbb(-1) & 3 = 3; 0x51 + 3 = 0x54 = 'T'
*unit_type_char = ((queue_count < 1 ? 3 : 0) & 3) + 0x51;
```

---

## System FM Sequence: Client-Side Orchestration

### tRFC / qRFC Submit + Confirm

```
conn.call_transactional("FM", tid=tid, ...)
    │
    ├─ 1. build_invoke_request("ARFC_DEST_SHIP", ...)  ← existing TLV writer
    │     ARFCSSTATE[0].ARFCTID_fields = encode_tid(tid)
    │     ARFCSDATA rows = serialized FM calls (one or more)
    │     [qRFC: ARFCSSTATE[0].queue_indicator = queue_name]
    ├─ 2. Transport.send_message()
    └─ 3. receive response (RFC_OK or RFC_EXECUTED from server)

conn.confirm_tid(tid)
    │
    └─ 1. build_invoke_request("ARFC_DEST_CONFIRM", ...)
          ARFCSSTATE[0].ARFCTID_fields = encode_tid(tid)
          ── after this, backend removes TID from ARFCRSTATE ──
```

**BN confirmation:**
- `ARFC_DEST_SHIP` registered as tRFC submit: `RfcServer::dispatch` 0x4bb5de, 0x4bb649
- `ARFC_DEST_CONFIRM` and `API_CLEAR_TID` as confirm: 0x4bb65a, 0x4bb697, → 0x4bb6bb

### bgRFC Submit + Confirm

```
with conn.create_unit(uid, queues=["Q1"]) as unit:
    unit.call("FM1", ...)   # buffered → RfcInvokeInUnit (BN 0x48c1da)
    unit.call("FM2", ...)   # buffered
# __exit__ → RfcSubmitUnit (BN 0x485944) → build_invoke_request("BGRFC_DEST_SHIP", ...)

conn.confirm_unit(identifier)
    └─ build_invoke_request("BGRFC_DEST_CONFIRM", ...)

conn.get_unit_state(identifier)
    └─ build_invoke_request("BGRFC_CHECK_UNIT_STATE_SERVER", ...)
```

**BN confirmation:** `RfcServer::dispatch` 0x4bb5de branches at 0x4bb6b1 (`BGRFC_DEST_SHIP`),
0x4bb713 (`BGRFC_DEST_CONFIRM`), 0x4bb733 (`BGRFC_CHECK_UNIT_STATE_SERVER`).

---

## Server-Side Dispatch (inbound tRFC/qRFC/bgRFC)

When an RFC server (registered via `RfcRegisterServer`) receives an inbound call, the full
dispatch path is:

```
RfcListenAndDispatch (0x77e4f0)
  → RfcConnectionBase::listen (0x78ff60)
  → RfcConnectionBase::dispatch (0x559bba)
  → RfcServer::dispatch (0x4bb5de)
       │
       ├─ strcmpU16(fname, "ARFC_DEST_SHIP")   → RfcTransaction::serveCall (0x4b7bac)
       │       → RfcTransaction::initByTables() → reads ARFCIPID/PID/TIME/TIDCNT
       │       → TransactionHandler::checkTransaction (0x5604fc) → calls RFC_ON_CHECK_TRANSACTION
       │                  returns RFC_EXECUTED (0x10) → RfcTransaction::playback (skip handler)
       │                  returns RFC_OK (0)           → store.mark_received; run handler
       │
       ├─ strcmpU16(fname, "ARFC_DEST_CONFIRM")→ RfcServer::invokeConfirmTransaction (0x4bb6bb)
       ├─ strcmpU16(fname, "BGRFC_DEST_SHIP")  → BgRfcUnit::serveCall (0x50f602)
       │       → BgRfcUnitHandler::checkUnit (0x50f668)
       │       → BgRfcUnit::playback (0x50f67a)
       └─ *(else)*                              → normal handler dispatch
```

**RFC_ON_CHECK_TRANSACTION callback contract (sapnwrfc.h:729):**
- Returns `RFC_EXECUTED` (value 0x10): TID known and executed → skip handler, return success
- Returns `RFC_OK` (value 0): new TID → persist and execute
- Returns `RFC_EXTERNAL_FAILURE` (value 0xf): handler error

**Callback order (confirmed by RfcTransaction::serveCall at 0x4b7bac and sapnwrfc.h:2436):**
```
check_transaction(tid)       → RFC_EXECUTED? → skip
mark_received(tid) BEFORE execute  ← crash-safety (persist before run)
run_handler()
  ├─ success → on_commit(tid); on_confirm(tid)
  └─ error   → on_rollback(tid)
```

---

## RFC_SERVER_CONTEXT: call-type field (inbound)

`RfcGetServerContext()` fills an `RFC_SERVER_CONTEXT` struct (sapnwrfc.h:352).
`RFC_SERVER_CONTEXT.type` is the `RFC_CALL_TYPE` enum:

| Enum Value | Constant | Meaning |
|------------|----------|---------|
| 0 | `RFC_SYNCHRONOUS` | Standard synchronous call |
| 1 | `RFC_TRANSACTIONAL` | tRFC (set from 0x1c20 path in getRfcServerContext) |
| 2 | `RFC_QUEUED` | qRFC (set when queue name byte != 0) |
| 3 | `RFC_BACKGROUND_UNIT` | bgRFC (set when 0x1c28 != 0) |

**BN source:** `RfcConnectionBase::getRfcServerContext` at 0x5536e4:
- `*entry_rsi = 3` at 0x553753: bgRFC (when `*(arg1 + 0x1c28) != 0`)
- `*rbx = 1` at 0x5537de: transactional (base case for non-bgRFC)
- `*rbx = 2` at 0x5537d1: queued (when `*(rdx_1 + 0x78) != 0` — queue-name indicator)
- Default (0): synchronous (memset to 0 at 0x553746)

---

## TID / UnitID Validation (security: TRFC-01..04, V5 input validation)

Inbound TID and UnitID values arrive as ABAP CHAR fields within the function parameters.
Before using them as store keys or for comparison:

| Field | Length | Valid charset | Action on invalid |
|-------|--------|--------------|-------------------|
| TID | exactly 24 chars (RFC_TID_LN) | `A-Z0-9/_=@-` | reject, return RFC_EXTERNAL_FAILURE |
| UnitID | exactly 32 chars (RFC_UNITID_LN) | `0-9A-F` (uppercase hex) | reject |
| Queue name | 1–`RFC_MAX_QUEUE_NAME_LENGTH` chars | ABAP name chars | reject empty/overlong |

**Sources:** sapnwrfc.h:79-82 (length constants), BN 0x4b5a33 (TID alphabet), BN 0x511855
(UnitID: `pfuuid_print` → 32-char hex), security threat T-06-TRFC-V5.

---

## Pitfalls (Phase 6 carry-forwards)

### Pitfall 1: Treating tRFC as a distinct frame type
tRFC is a synchronous call to `ARFC_DEST_SHIP`. Use `build_invoke_request()` unchanged.

### Pitfall 2: Wrong TID character set
TID uses `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-` (41 chars), NOT hex digits. A
`uuid4().hex[:24].upper()` value is a valid subset but NOT the authentic format.
**BN confirmed at 0x4b5a33.**

### Pitfall 3: Confirm before success
Calling `confirm_tid()` removes backend dup protection before verifying the call landed.
`call_transactional` (submit) and `confirm_tid` (confirm) must stay separate (D-04).

### Pitfall 4: Off-by-2x on TID/UnitID byte length
TID = 24 chars × 2 bytes/char = 48 bytes UTF-16LE. UnitID = 32 × 2 = 64 bytes.
All length arithmetic is in code units (2 bytes), not Python `len()`. (CLAUDE.md carry-forward.)

### Pitfall 5: bgRFC unit type 'T' vs 'Q'
`RFC_UNIT_IDENTIFIER.unitType` must match exactly:
- `'T'` when no queues (`queues=[]`)
- `'Q'` when queues specified (`queues=["QNAME"]`)
**BN confirmed at 0x483919.**

### Pitfall 6: call-type discriminator implementation
In `server.py:391` seam: the discriminator is the **function name string** in TLV 0x0102,
NOT a separate byte. Branch on the decoded function name before the normal handler lookup.
**BN confirmed at RfcServer::dispatch 0x4bb5de.**

---

## Open Gaps (live capture not yet obtained — D-08 gate)

The following items are **documented as open gaps** per the no-guessing policy (D-09):

| Gap ID | Item | Resolution |
|--------|------|-----------|
| OG-06-01 | Exact byte layout of ARFCSSTATE table row in ARFC_DEST_SHIP invoke frame | **PARTIALLY CLOSED** — D-08 live capture (2026-07-05) confirmed the 5001 NgRfc compact block. CHAR values encoded as `0x43 [len] 0x80 [value]`. TID fields (ARFCIPID/PID/TIME/TIDCNT) at offsets 504/515/522/533 (8+4+8+4 uppercase hex chars), ARFCFNAM at 1716. Preamble bytes `34 08 0c 00 00 4c 07 00 00 f1 31` at offset 14 unresolved (not blocking). |
| OG-06-02 | Exact BGRFC_DEST_SHIP payload byte layout | **OPEN** — bgRFC live test used empty `{}` params; no payload bytes captured for bgRFC function params. |
| OG-06-03 | Whether ARFC_EXECUTE or ARFC_RUN_NOWAIT is called separately from ARFC_DEST_SHIP | **OPEN** — BN shows only ARFC_DEST_SHIP in dispatch; no ARFC_EXECUTE frame observed. |
| OG-06-04 | Exact TID string format for server-originated TIDs (vs client-side local gen) | **CLOSED** — D-08 live capture (2026-07-05): TID = `C0A8580746006A4AA9F40003` = ARFCIPID(8)+ARFCPID(4)+ARFCTIME(8)+ARFCTIDCNT(4) all uppercase hex. IP 192.168.88.7=C0A85807, PID=4600, time=6A4AA9F4, cnt=0003. TID alphabet confirmed 24-char uppercase hex subset. |

---

## BN RE Cross-Reference Summary

| BN Address | Function | Finding |
|------------|----------|---------|
| 0x4bb5de | `RfcServer::dispatch` | Function-name IS the call-type discriminator; ARFC_/BGRFC_ FM names |
| 0x4bb632 | `RfcServer::dispatch` + ARFC_DEST_SHIP check | tRFC branch; 0xe58 byte = qRFC indicator |
| 0x4b5962 | `RfcTransaction::createTid` | TID = IP+PID+time+count, alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@- |
| 0x4b5a33 | `RfcTransaction::createTid` | Confirmed 41-char alphabet |
| 0x4b681e | `getArfcDestShipFunctionDesc` | Full ARFCSSTATE field layout for ARFC_DEST_SHIP |
| 0x4b7bac | `RfcTransaction::serveCall` | Server tRFC: checkTransaction → playback on RFC_EXECUTED |
| 0x5604fc | `TransactionHandler::checkTransaction` | Callback dispatch, RFC_EXECUTED short-circuit |
| 0x50b846 | `BgRfcUnit::getBgrfcDestShipFuncMeta` | BGRFC_DEST_SHIP parameter layout |
| 0x511554 | `BgRfcUnit::createUnitId` | UnitID = 32-char uppercase hex UUID |
| 0x511855 | `BgRfcUnit::createUnitId` | pfuuid_print asserts len == 32 (0x20) |
| 0x483919 | `RfcCreateUnit` | unit_type = 'Q' (0x51) or 'T' (0x54) based on queue count |
| 0x5536e4 | `RfcConnectionBase::getRfcServerContext` | RFC_CALL_TYPE enum values 0–3 filled from connection state |
| 0x4b8578 | `RfcTransaction::getTid` | Calls API_CREATE_TID FM via ContextBase::rfcCallReceive |
| 0x77e4f0 | `RfcListenAndDispatch` | Inbound server receive loop; calls RfcConnectionBase::listen |
| 0x4afdfe | `RfcParameter::rfcSerialize` | type-switch confirms STRING(0x1d)→writeRfcUTF8Chars(UTF-8/4110); XSTRING(0x1e)→writeRfcData(raw); INT8/UTCLONG group=LE 8B; DTDAY group=LE 4B; TMINUTE group=LE 2B |
| 0x552aac | `RfcConnectionBase::writeRfcUTF8Chars` | STRING wire: SAP cp4110 (UTF-8) conversion then writeRfcData — no internal length prefix |
| 0x551560 | `RfcConnectionBase::writeRfcIDBegin` | Writes TLV header: `[tag BE 2B][len BE 2B]` or `[tag][0xFFFF][len BE 4B]` if len≥0xFFFF |

---

*Phase 6 RE findings. See `.planning/bn-re-findings.md §"Phase 6 cross-reference"` for the index.*
*docs/protocol/framing.md and docs/protocol/handshake.md document the framing and logon layers.*
