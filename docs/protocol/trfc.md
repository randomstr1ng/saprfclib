# tRFC / qRFC / bgRFC Wire Protocol

**Status:** CONFIRMED for the call-type discriminator and structural format. Live capture
2026-07-05 confirmed TID composition and the ARFCSSTATE field positions.
**Confidence:** HIGH for the discriminator and structure; MEDIUM for the exact byte-level
encoding of individual payload fields — see [Known Gaps](#known-gaps).

---

## Overview

tRFC, qRFC and bgRFC are **not distinct wire frame types**. They are ordinary synchronous RFC
calls to SAP *system* function modules. The call type is discriminated entirely by the
**function name** carried in the standard `0x0102` TLV tag — see
[framing.md](framing.md) §"RFC Function Call Sequence". The normal invoke/dispatch paths are
reused unchanged for the payload; the transactional layer is orchestration on top.

```
tRFC / qRFC = synchronous RFC invoke of ARFC_DEST_SHIP  (carrying TID in ARFCTID param)
            + optional later invoke of ARFC_DEST_CONFIRM
bgRFC       = synchronous RFC invoke of BGRFC_DEST_SHIP (carrying UnitID in BGRFC_UNIT_ID param)
            + optional later invoke of BGRFC_DEST_CONFIRM
```

This is the single most useful fact on this page. If you are looking for a tRFC frame type in a
capture, you will not find one — look for the function name instead.

---

## Call-Type Discriminator

The discriminator is the **function name TLV (tag `0x0102`, UTF-16LE)** in the inbound invoke
frame. A server compares the decoded name against the system function-module names below
*before* falling through to its normal handler lookup:

| Function name (`0x0102` TLV value) | Call type |
|------------------------------------|-----------|
| `ARFC_DEST_SHIP` | tRFC — or qRFC, see below |
| `ARFC_DEST_CONFIRM` | tRFC confirm |
| `API_CLEAR_TID` | Internal TID clear |
| `BGRFC_DEST_SHIP` | bgRFC submit |
| `BGRFC_DEST_CONFIRM` | bgRFC confirm |
| `BGRFC_CHECK_UNIT_STATE_SERVER` | bgRFC state query |
| *(any other name)* | Ordinary synchronous RFC |

**tRFC vs qRFC:** both arrive as `ARFC_DEST_SHIP`. The difference is a queue-name indicator
carried in the `ARFCSSTATE` table parameter — when a queue name is present, the call is qRFC
(queued). There is no separate function name and no separate frame type.

---

## tRFC Wire Format: ARFC_DEST_SHIP

A tRFC submit is a standard synchronous call to `ARFC_DEST_SHIP`. The frame is an ordinary
invoke frame as defined in [framing.md](framing.md), with `ARFC_DEST_SHIP` in TLV `0x0102` and
the parameters below.

The call carries two tables: `ARFCSSTATE` (the control record, one row) and `ARFCSDATA`
(payload rows, one per ABAP function module invoked in the LUW).

### ARFCSSTATE control-record fields

`NUC` = non-Unicode size, `UC` = Unicode (UTF-16) size. Offsets are non-Unicode.

| ABAP field | Type | NUC size | UC size | NUC offset | Notes |
|------------|------|----------|---------|------------|-------|
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

### The 24-character TID

The TID is a 24-character string over a **non-hexadecimal** alphabet:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-      (41 characters, uppercase)
```

It is built from four 4-byte words, each encoded as 6 characters by repeated modulo-41 into
that alphabet — 4 × 6 = 24 characters:

1. `own_ip` — 4 bytes of the local IP address (resolved once per process)
2. `pid` — the process ID (4 bytes, resolved once per process)
3. `time` — Unix seconds (4 bytes)
4. `tidCount` — an atomically incremented counter

**Wire encoding:** as ABAP CHAR values inside the `ARFCIPID` / `ARFCPID` / `ARFCTIME` /
`ARFCTIDCNT` fields of the `ARFCSSTATE` row. The 24-character TID a client API hands you is the
concatenation of those four fields — it is **not** sent as a standalone TLV tag. Looking for a
"TID tag" in a capture is a dead end.

**Live confirmation (2026-07-05):** a captured TID of `C0A8580746006A4AA9F40003` decomposes as
`ARFCIPID` (8) + `ARFCPID` (4) + `ARFCTIME` (8) + `ARFCTIDCNT` (4), all uppercase hex —
IP `192.168.88.7` = `C0A85807`, PID `4600`, time `6A4AA9F4`, counter `0003`.

!!! note "A UUID-derived TID is valid, but is not the native format"
    `uuid4().hex[:24].upper()` yields characters from `0-9A-F`, a strict subset of the TID
    alphabet. The server range-checks the alphabet only, so such a TID is accepted. The native
    format is the IP + PID + time + counter encoding above, and using it makes TIDs traceable
    back to their originating host and process — which is worth having when debugging a stuck
    LUW.

---

## qRFC: Queue-Name Discrimination

qRFC is tRFC plus a queue name, sent through the **same `ARFC_DEST_SHIP`** function module. The
queue name travels in the `ARFCSSTATE` table parameter; a non-empty queue-name indicator is what
makes the call queued.

Queue names are bounded — a maximum length applies, and a unit may carry more than one. Reject
empty and overlong names on the inbound path rather than passing them to a store.

---

## bgRFC Wire Format: BGRFC_DEST_SHIP

bgRFC uses its own function module, `BGRFC_DEST_SHIP`:

| ABAP parameter | Type | Notes |
|----------------|------|-------|
| `OUT_IN_QUEUE_NAME_TAB` | TABLE | Queue name(s) for this unit |
| `ARFCSDATA` | XSTRING | Serialized payload — the function calls buffered in the unit |
| `ARFCSTATE` | STRUCTURE | State record |
| `SUPPORTABILITY_INFO` | STRUCTURE | Supportability metadata |
| `BGRFC_RETRY_DELAY_TIME` | INT4 | Retry delay, seconds |
| `BGRFC_RETRY_KEY` | CHAR | Retry key (24 characters) |
| `BGRFC_RETRY_MAX_COUNT` | INT4 | Maximum retry count |
| `SERVER_STATE` | INT4 | Execution state indicator |

### The 32-character UnitID

A UnitID is **32 uppercase hex characters** — a UUID with the dashes removed.

- **With a connection:** the client round-trips to `BGRFC_GET_UNIT_ID`, receives a 16-byte
  UUID, and formats it as 32 uppercase hex characters.
- **Without a connection:** the UUID is generated locally and formatted identically.

Example: `A1B2C3D4E5F6789012345678901234AB`

### Unit type character

| Character | Meaning |
|-----------|---------|
| `'T'` (0x54) | No queue names — synchronous execution |
| `'Q'` (0x51) | One or more queue names specified |

The rule is exactly "queue count < 1 → `'T'`, otherwise `'Q'`". It must match the queue list you
actually send; a mismatch is rejected by the backend.

---

## Client-Side Orchestration

### tRFC / qRFC submit and confirm

```
conn.call_transactional("FM", tid=tid, ...)
    │
    ├─ 1. build_invoke_request("ARFC_DEST_SHIP", ...)
    │     ARFCSSTATE[0].ARFCTID_fields = encode_tid(tid)
    │     ARFCSDATA rows = serialized FM calls (one or more)
    │     [qRFC: ARFCSSTATE[0].queue_indicator = queue_name]
    ├─ 2. Transport.send_message()
    └─ 3. receive response (RFC_OK or RFC_EXECUTED from server)

conn.confirm_tid(tid)
    │
    └─ 1. build_invoke_request("ARFC_DEST_CONFIRM", ...)
          ARFCSSTATE[0].ARFCTID_fields = encode_tid(tid)
          ── after this, the backend removes the TID from its state table ──
```

### bgRFC submit and confirm

```
with conn.create_unit(uid, queues=["Q1"]) as unit:
    unit.call("FM1", ...)   # buffered, not sent yet
    unit.call("FM2", ...)   # buffered
# __exit__ → build_invoke_request("BGRFC_DEST_SHIP", ...)

conn.confirm_unit(identifier)
    └─ build_invoke_request("BGRFC_DEST_CONFIRM", ...)

conn.get_unit_state(identifier)
    └─ build_invoke_request("BGRFC_CHECK_UNIT_STATE_SERVER", ...)
```

---

## Server-Side Dispatch

When a registered RFC server receives an inbound call, the function name is matched before the
normal handler lookup:

```
inbound frame
  → decode function name from TLV 0x0102
       │
       ├─ "ARFC_DEST_SHIP"     → read TID from ARFCIPID/PID/TIME/TIDCNT
       │                         → check_transaction(tid)
       │                              RFC_EXECUTED (0x10) → skip the handler, report success
       │                              RFC_OK (0)          → mark received, run the handler
       │
       ├─ "ARFC_DEST_CONFIRM"  → confirm the transaction, drop duplicate protection
       ├─ "BGRFC_DEST_SHIP"    → check the unit, then play it back
       └─ *(else)*             → ordinary handler dispatch
```

### check_transaction callback contract

| Return | Meaning |
|--------|---------|
| `RFC_EXECUTED` (0x10) | TID already known and executed → skip the handler, return success |
| `RFC_OK` (0) | New TID → persist it and execute |
| `RFC_EXTERNAL_FAILURE` (0xf) | Handler error |

### Callback order

```
check_transaction(tid)            → RFC_EXECUTED? → skip
mark_received(tid) BEFORE execute ← crash safety: persist before you run
run_handler()
  ├─ success → on_commit(tid); on_confirm(tid)
  └─ error   → on_rollback(tid)
```

`mark_received` **before** execution is what makes exactly-once survive a crash mid-handler. If
you persist afterwards, a process death between execution and persistence replays the LUW.

---

## Server context: call type

The inbound call type is exposed to the handler as:

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `RFC_SYNCHRONOUS` | Standard synchronous call |
| 1 | `RFC_TRANSACTIONAL` | tRFC |
| 2 | `RFC_QUEUED` | qRFC — set when a queue name is present |
| 3 | `RFC_BACKGROUND_UNIT` | bgRFC |

---

## TID / UnitID Validation

Inbound TID and UnitID values arrive as ABAP CHAR fields inside function parameters. They are
attacker-influenced input and become store keys, so validate before use:

| Field | Length | Valid charset | Action on invalid |
|-------|--------|---------------|-------------------|
| TID | exactly 24 characters | `A-Z0-9/_=@-` | Reject, return `RFC_EXTERNAL_FAILURE` |
| UnitID | exactly 32 characters | `0-9A-F` (uppercase hex) | Reject |
| Queue name | 1 to the maximum queue-name length | ABAP name characters | Reject empty or overlong |

---

## Pitfalls

### 1. Treating tRFC as a distinct frame type
It is a synchronous call to `ARFC_DEST_SHIP`. Use `build_invoke_request()` unchanged.

### 2. Wrong TID character set
The TID alphabet is `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-` (41 characters), not hex
digits. A `uuid4().hex[:24].upper()` value is a valid subset but not the native format.

### 3. Confirming before success
`confirm_tid()` removes the backend's duplicate protection. Calling it before you have verified
the call landed defeats exactly-once. Submit and confirm are deliberately separate calls —
keep them that way.

### 4. Off-by-2× on TID / UnitID byte length
TID = 24 characters × 2 bytes = 48 bytes UTF-16LE. UnitID = 32 × 2 = 64 bytes. All length
arithmetic is in code units, not Python `len()`.

### 5. bgRFC unit type `'T'` vs `'Q'`
The unit type must match the queue list exactly: `'T'` when `queues=[]`, `'Q'` when queues are
specified.

### 6. Looking for a call-type byte
The discriminator is the **function name string** in TLV `0x0102`, not a separate byte. Branch
on the decoded function name before the normal handler lookup.

---

## Known Gaps

### ARFCSSTATE row byte layout — PARTIALLY CONFIRMED

A live capture on 2026-07-05 confirmed the compact block encoding: CHAR values appear as
`0x43 [len] 0x80 [value]`, with the TID fields (`ARFCIPID` / `ARFCPID` / `ARFCTIME` /
`ARFCTIDCNT`) at offsets 504 / 515 / 522 / 533 as 8 + 4 + 8 + 4 uppercase hex characters, and
`ARFCFNAM` at 1716. An 11-byte preamble at offset 14 —
`34 08 0c 00 00 4c 07 00 00 f1 31` — is unexplained. It is stable across captures and not
blocking, but it violates the zero-unknowns rule and is recorded rather than glossed over.

### BGRFC_DEST_SHIP payload byte layout — OPEN

The live bgRFC test submitted a unit with empty parameters, so no payload bytes were captured
for bgRFC function parameters. **Consequence:** the bgRFC payload encoding is inferred from the
tRFC path rather than confirmed. **To close:** capture a bgRFC unit carrying real parameters.

### ARFC_EXECUTE / ARFC_RUN_NOWAIT — OPEN

Whether either is ever called separately from `ARFC_DEST_SHIP` is unconfirmed. Only
`ARFC_DEST_SHIP` has been observed in dispatch, and no `ARFC_EXECUTE` frame has appeared in any
capture.

---

*See also: [Framing](framing.md) and [Handshake](handshake.md) for the framing and logon layers.*
