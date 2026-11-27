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
| `ARFC_DEST_CONFIRM` | inbound only: ABAP confirming a TID to a registered server (Inbound tRFC) |
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
declarations (nothing comes back) and no `0x0330` table ids. Deep parameters travel in it as
in an ordinary call, one `0x3c02`/`0x3c05` XML bracket each ([Serialization](serialization.md#deep-parameters-xml-in-0x3c02-0x3c05);
tRFC and qRFC capture 2026-11-26, `tests/golden/serialization/deep/deep_unit_calls.json`). The same header precedes the
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
saprfclib accepts `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-`. A live server ran a tRFC under a
TID made of any of these, and also under one with lowercase letters, a space or `#` (probe,
ABAP Platform 2025, 2026-11-27: ten TIDs, each recorded as `FINISHED` in `ARFCRSTATE`). The set
is saprfclib's own, narrower than what the server takes, because a TID keys the durable stores.

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
  sends" below: `1409196105` for a type `T` unit and `1409196103` for a type `Q` unit,
  in the submit, the state query and the confirm alike (live captures, 2026-11-26). `'Q'` was
  `[ASSUMED]` as `1409196101` by symmetry before that capture; a state query with that value
  reports a real queued unit as missing.

### The two simple modules

`BGRFC_DEST_CONFIRM` and `BGRFC_CHECK_UNIT_STATE_SERVER` take the unit ID
directly rather than through a structure:

| Module | IMPORT | EXPORT |
|--------|--------|--------|
| `BGRFC_DEST_CONFIRM` | `UNIT_ID` BYTE(16), `UNIT_KIND` INT4, five optional `RS_*` | `RS_SERVER_RESOURCES_RC` INT4, `RS_SYSTEM_IDENTITY` |
| `BGRFC_CHECK_UNIT_STATE_SERVER` | `UNIT_ID` BYTE(16), `UNIT_KIND` INT4 | `STATE` INT4, `INSTANCE_NAME`, `MAX_WPRUN_TIME`, `COMMUNICATION_FAILURE`, `SYSTEM_FAILURE` |
| `BGRFC_GET_UNIT_ID` | — | `UNIT_ID` BYTE(16) |

Both are ordinary signatures the dictionary describes, so neither needs a bespoke
TLV builder — the normal invoke path encodes them.

`BGRFC_CHECK_UNIT_STATE_SERVER`'s `STATE` (INT4), read live from units saprfclib submitted,
at each point of their life (ABAP Platform 2025, 2026-11-27, `tests/golden/trfc/bgrfc_states.json`):

| STATE | The unit |
|-------|----------|
| 22206 | was never submitted |
| 22201 | is running its call |
| 22202 | ran and committed |
| 22203 | was confirmed |
| 22208 | failed in its call |

`invoke.unit_state_from_wire` maps each to the `UnitState` of the same meaning; any other
value is reported as unrecognised rather than given a name. `BGRFC_GET_UNIT_ID` works and
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

## Re-driving a parked request

A parked request is the invoke frame its first connection built: the GW header with that
connection's handle and index, the request body, the 8-byte footer. Sent as it is on any later
connection, the gateway refuses it, `Conversation NNNN not found`. Probe, ABAP Platform 2025,
2026-11-26, both ways a submit gets parked: the send dropped before it reached the server, and
the server ran the call and the reply was lost. So `retry_parked` and `retry_parked_unit` keep
the body, including the logon header of the serialized calls in it, and rebuild the frame
around it from the connection they send on. Framed that way, the call that had never arrived
ran once (one `ARFCRSTATE` entry, its values stored), and the one that had already run was
accepted and not run again (its `ARFCRSTATE` entry unchanged, a value overwritten in between
left as it was). bgRFC re-drives use the same framing; that path is tested offline only.

## Client-Side Orchestration

### tRFC / qRFC submit and confirm

```
conn.call_transactional("FM", tid=tid, queue=None, **params)
    │
    ├─ 1. metadata of FM and of ARFC_DEST_SHIP (cached)
    ├─ 2. serialize the call: header from the logon + build_invoke_request(transactional=True)
    ├─ 3. build_trfc_request: STATE row (TID, FM, queue), DATA rows (the serialized call)
    ├─ 4. send, read the reply; an error raises
    └─ on CommunicationError: the session is retired, a new connection is opened and
       logged on, and the call is built again for it and resent with the same TID

conn.confirm_tid(tid)
    └─ API_CLEAR_TID with the TID -- the server forgets it
```

One call per TID: the reference client can put several calls into one LUW, the public API
sends one.

**A retry never reuses the failed connection.** After a failed send or an unread reply the
byte stream is out of step: a resend on it could be read as the tail of the previous frame, or
the old reply taken for the answer to the new request. So the session is marked broken, the
transport closed, and a new connection opened over the same route (SAProuter and proxy
included) and logged on. The request is then built again from the new session, since its GW
handle, connection index and the logon header in the call all change, and sent with the
**same TID**.

That is safe because the server keeps a TID across connections. Behavioural probe
(2026-11-25, kernel 793): submit `STFC_CONNECTION` under a TID on one connection, close it,
submit the same TID on a new connection: `ARFCRSTATE` holds one entry, `FINISHED`, before and
after the resubmit, and none after `API_CLEAR_TID`. A reconnect that fails counts as a failed
attempt; when the attempts are exhausted the request is parked and `RetryExhausted` raised,
and the connection stays retired. Connections that do not run on the async core (SNC) do not
retry; a transport failure there retires the session and raises.

Exercised over real sockets by `tests/test_scripted_peer.py`, which serves captured frames
from a loopback peer and breaks the connection during the submit (reset, truncated reply,
half-close).

### bgRFC submit and confirm

```
with conn.create_unit(uid, queues=["Q1"]) as unit:
    unit.call("FM1", ...)   # buffered, not sent yet
    unit.call("FM2", ...)   # buffered
# __exit__ → each call serialized as a tRFC call (build_trfc_call) → build_bgrfc_sdata
#   → BGRFC_DEST_SHIP with SDATA, SSTATE, SUPPORTABILITY_INFO, SHUTDOWN_ACTIVE and
#   OUT_IN_QUEUE_NAME_TAB, through the ordinary request builder (see "bgRFC SDATA").

conn.confirm_unit(identifier)
    └─ build_invoke_request("BGRFC_DEST_CONFIRM", ...)

conn.get_unit_state(identifier)
    └─ build_invoke_request("BGRFC_CHECK_UNIT_STATE_SERVER", ...)
```

---

## Server-Side Dispatch

When a registered RFC server receives an inbound call, the function name is matched before the
normal handler lookup. ABAP sends a tRFC or qRFC LUW as `ARFC_DEST_SHIP` and a bgRFC unit as
`BGRFC_DEST_SHIP` (Inbound tRFC and Inbound bgRFC, below).

```
inbound frame
  → decode function name from TLV 0x0102
       │
       ├─ "ARFC_DEST_SHIP"     → the TID and the calls from STATE / DATA (Inbound tRFC)
       │                         → on_check(tid), or the TID store
       │                              16 (executed) → run nothing, answer success
       │                              0 (new)       → mark received, run the calls
       ├─ "ARFC_DEST_CONFIRM"  → the TID from CALLID; confirms it
       ├─ "BGRFC_DEST_SHIP"    → the unit from SSTATE, its calls from SDATA (Inbound bgRFC,
       │                         below); checks the unit, then runs its calls in order
       ├─ "BGRFC_DEST_CONFIRM" → UNIT_ID / UNIT_KIND; confirms the unit
       └─ *(else)*             → ordinary handler dispatch
```

### on_check callback contract

`install_transaction_handlers(on_check=...)`:

| Return | Meaning |
|--------|---------|
| 16 (`RFC_EXECUTED`) | TID already known and executed → skip the handler, return success |
| 0 (`RFC_OK`) | New TID → persist it and execute |

16 is the callback's answer, as in the SDK's API, not a wire value: an executed TID is answered
as a LUW that ran (Inbound tRFC, below), and a failure as `0x0402` with the message.

### Callback order

```
on_check(tid)                     → 16? → skip
mark_received(tid) BEFORE execute ← crash safety: persist before you run
run the calls, in order, stopping at the first failure
  ├─ success → mark_executed(tid); on_commit(tid)   (on_confirm only on a confirm)
  └─ error   → mark_rolled_back(tid); on_rollback(tid)
```

`mark_received` **before** execution is what makes exactly-once survive a crash mid-handler. If
you persist afterwards, a process death between execution and persistence replays the LUW.

---

## TID / UnitID Validation

Inbound TID and UnitID values arrive as ABAP CHAR fields inside function parameters. They are
attacker-influenced input and become store keys, so validate before use:

| Field | Length | Valid charset | Action on invalid |
|-------|--------|---------------|-------------------|
| TID | exactly 24 characters | `A-Z0-9/_=@-` | Reject with a system failure (a `0x0402` message, no return code) |
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
TIDs SAP issues are 24 uppercase hex characters. The server accepts more (The 24-character
TID, above); saprfclib accepts `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-`, and `create_tid()`
makes uppercase hex.

---

## bgRFC SDATA

`BGRFC_DEST_SHIP` takes the unit's calls in `SDATA`, an XSTRING. From live captures of the
reference client (pyrfc 3.3.1 on the NW RFC SDK 7.50) submitting six units on ABAP
Platform 2025 (kernel 916), 2026-11-26, that differ in one way each: one call, two calls, a
function with no parameters, a longer value, a deep parameter, a queued unit
(`tests/golden/trfc/bgrfc_reference.json`, sanitised). Each committed; the one with a deep
parameter ran and stored the values sent.

    container    FF 06 02 01 02 02 80 00 | codepage, 4 ASCII digits ("4103") |
                 00 00 00 00 | SAPCOMPRESS LZH block of the plaintext
    plaintext    06 0F 00 00 00 00 50 | total length - 120, BE uint32 |
                 113 constant bytes naming SER_UNIT_TAB | number of calls, BE uint32 |
                 per call:  BC 00 00 00 3C | function name, 30 characters blank-padded,
                            UTF-16LE | 55 constant bytes carrying the option string
                            basxml=0, | record length, BE uint32 | record | CB BF
                 BF 04
    record       the call exactly as a tRFC submit's DATA rows carry it
                 (A serialized call, above): the logon header, then the call without
                 0x0512, 0x0205 declarations or table ids; deep parameters in XML
                 brackets as in an ordinary call

Built from these parts, all six plaintexts are reproduced byte for byte, and every record but
the deep ones equals `build_trfc_call`'s output for the same call (the deep ones differ only in
writing an untouched nested component as its initial value, which the server reads the same;
see Serialization). The constant parts are constant across all six; what their tags mean is not
needed to write them and is not claimed here.

**Compression.** The block is SAPCOMPRESS LZH: header `<length LE uint32> 12 1F 9D 02`, then a
2-bit noise count (0) and DEFLATE blocks with a 16 KB window. saprfclib writes the blocks with
the standard library's `zlib`, and falls back to a single fixed-Huffman block of literals for
data DEFLATE would store (the decoder has no stored blocks). The reference client's blocks are
within a few bytes of the same size.

**The rest of the submit.** `SSTATE` carries `UNIT_ID` as 16 raw bytes and `UNIT_KIND`;
`SUPPORTABILITY_INFO` the same two; `SHUTDOWN_ACTIVE` a blank; `OUT_IN_QUEUE_NAME_TAB` the
queue names, as an XML table of elementary rows, empty for a `T` unit. `SSTATE-QUEUE_NAME`
stays empty even for a `Q` unit. The reference client also fills these, all informational:

| `SSTATE` field | Reference client | saprfclib |
|----------------|------------------|-----------|
| `DESTINATION` | `<unknown>` on kernel 916, the client host on 793 | the client host |
| `CALLER_CLIENT` | `000` | `000` |
| `CALLER_USER` | the operating-system user | the logon user |
| `CALLER_TCODE` | `NW RFC Library 754` | `saprfclib` |
| `CALLER_PROGRAM` | the executable name | the logon program name |
| `SENDING_TIME` | local time one month behind, in every capture | current UTC time |
| `SENDING_INSTANCE` | the client host | the client host |

The unit id need not come from the server: the reference client asks `BGRFC_GET_UNIT_ID`,
saprfclib generates 16 random bytes, and both were accepted.

**Live, saprfclib, 2026-11-26.** A one-call, a two-call, a deep-parameter and a queued unit
were submitted, read back as `COMMITTED` by `BGRFC_CHECK_UNIT_STATE_SERVER`, and confirmed; the
deep-parameter unit ran and stored exactly the values sent. The system had no supervisor
destination configured (`BGRFC_CUST_SUPER` empty): units still ran, inline in the submit, so
the note under Backend tables below does not hold for direct submits on this release.

## Inbound tRFC

How ABAP sends a tRFC or qRFC LUW to a registered server. From live captures on ABAP Platform
2025 (kernel 916), 2026-11-27 (`tests/golden/trfc/trfc_inbound.json`, sanitised): ABAP ran
`CALL FUNCTION ... IN BACKGROUND TASK DESTINATION` for a registered TCP/IP destination, and for
qRFC called `TRFC_SET_QUEUE_NAME` first. The receiving server was first one built on the NW RFC
SDK 7.50 with its transaction handlers installed, then `RfcServer`. Three LUWs: one call;
three calls, the second with a deep structure and a string table; and one call in a qRFC queue.
The destination had basXML on; with it off, the same LUWs arrived in the same form.

**The LUW** arrives as an `ARFC_DEST_SHIP` call with the `STATE` and `DATA` tables a client
submits (Submit, above): one `STATE` row per call, and each call serialized into the
`ARFCDATAnn` columns of its `DATA` rows. The TID is in the first four columns of every row.
How the rows arrive differs from a client's submit:

* `DATA` rows come as `0x0303` records of 1917 bytes, the used width of the 1918-byte layout.
* `STATE` rows come as compressed `0x0304` records of **955** bytes, where the layout is 972:
  each row is cut after its last byte, `00`, and restored by repeating it to the declared width
  (framing.md, `0x0304`). So `HASH`, RAW(40) at 932, is `00 02` + 20 bytes + 18 zero bytes.
* ABAP fills the columns a client leaves blank: `ARFCDEST` (the destination), `ARFCSTATE`
  (`SENDED`), the time, date and user. A qRFC LUW carries `O` + the queue name from character
  44 of `ARFCRESERV`; a client's inbound qRFC submit writes `I` there.
* Each serialized call has the logon header, then the call with its `0x0512` and `0x0205`
  declarations and its values, deep ones as XML. A client's call has no `0x0512`/`0x0205`.

The row layouts are `ARFC_DEST_SHIP`'s, so `RfcServer` reads them with the system's own
descriptor, given once with `set_trfc_descriptors()`. Without it, a LUW is answered with a
failure that names the method.

**The answers.**

| Case | SDK server's answer | `RfcServer`'s answer | Then ABAP (both servers) |
|------|---------------------|----------------------|--------------------------|
| LUW ran | `STATE` and `DATA` at their declared widths, no rows | the same tables, after `0x0500` / `0x0420` 0 | sent `ARFC_DEST_CONFIRM`, `ERRORSTATUS` 0, and removed the TID from its state table |
| a call raised | `0x0402` with the message | the same | sent `ARFC_DEST_CONFIRM`, `ERRORSTATUS` 1, in a new conversation; kept the TID as `SYSFAIL` with the message, to retry |
| check reported the TID as executed | `STATE` and `DATA` with their rows echoed | as for a LUW that ran | sent `ARFC_DEST_CONFIRM`, `ERRORSTATUS` 0 |

The SDK server's answer kept the conversation open (`0x06CB`), and ABAP sent the confirm in it.
`RfcServer` closes it (`0x0608`), and ABAP sent the confirm in a new conversation. Both worked.

**`ARFC_DEST_CONFIRM`** carries `CALLID` (`ARFCCALLID`: the four TID columns, `ARFCDEST`,
`ARFCLUWCNT`), `ERRORSTATUS` and `RETUDATA`. The SDK server's handlers saw a confirm after a
failure too, and `RfcServer` releases the TID either way, as the SDK does.

The compact `0x5001` block recorded on 2026-07-05 (Known Gaps) did not appear in these
captures, with basXML on or off.

## Inbound bgRFC

How ABAP sends a bgRFC unit to a registered server. From live captures on ABAP Platform 2025
(kernel 916), 2026-11-26 (`tests/golden/trfc/bgrfc_inbound.json`, sanitised): ABAP created
units with `CL_BGRFC_DESTINATION_OUTBOUND` for a registered TCP/IP destination and committed
them, first with the reference SDK's server (pyrfc 3.3.1 on the NW RFC SDK 7.50) registered,
then with `RfcServer`. Three units: one call; a deep-parameter call and a second call; one
call in an outbound queue.

**The conversation.** Each unit arrives as a `BGRFC_DEST_SHIP` call on a conversation of its
own. Once that call is answered as a success, ABAP opens another conversation and sends
`BGRFC_DEST_CONFIRM` with `UNIT_ID` (16 raw bytes) and `UNIT_KIND` (LE INT4). It did this
for every unit that ran, and for none whose answer was a failure.

**The unit.** `BGRFC_DEST_SHIP` has the parameters in the table above, and the unit is laid
out as the client writes it:

* `SDATA` is the container of "bgRFC SDATA" above, byte for byte in its constant parts, with
  each call's record in the tRFC form, deep parameters as XML. One parser reads ABAP's units
  and the reference client's.
* `SSTATE` carries `UNIT_ID` at 0 and `UNIT_KIND` at 16 as in a submit, but with the
  outbound kinds: `1409196105` for a `T` unit, `1409196101` for a `Q` unit. The client's
  queued submit carries `1409196103`.
* For a `Q` unit, `SSTATE-QUEUE_NAME` holds the queue (`ZSAPRFCLIB_OQ` in the capture) and
  `OUT_IN_QUEUE_NAME_TAB` is empty. A client submit is the other way round.

**The answer.** After a unit ran, the reference server answered with `BGRFC_RETRY_DELAY_TIME`
0, `BGRFC_RETRY_KEY` blank, `BGRFC_RETRY_MAX_COUNT` 0, `SERVER_STATE` 22202 (LE INT4),
`SHUTDOWN_INSTANCE` and `SHUTDOWN_ACTIVE` blank. It sends the two `SHUTDOWN_*` values even
though the request does not ask for them. `RfcServer` sends the same six values. ABAP confirmed
each unit after receiving them.

**What ABAP did with each answer** (probe, same session; `RfcServer`'s answers):

| Case | Answer | ABAP |
|------|--------|------|
| unit ran | the six values above | sent `BGRFC_DEST_CONFIRM` |
| a call's handler raised | `0x0402` with the message, as for any failed call | no confirm; kept the unit and recorded the message as its error, to retry |
| the check callback reported the unit as executed | the six values, no handler run | sent `BGRFC_DEST_CONFIRM` |

The reference server did something different in two of these cases. When a handler raised, it
rolled the unit back but answered with the six success values, so ABAP confirmed a unit that
had not run. When its check callback reported the unit as executed, it answered with the
failure "Application's transaction state database currently unavailable.", so ABAP kept the
unit and sent it again later. `RfcServer` reports a failure as a failure, and an executed unit
as done.

`RfcServer` stops at the first call that fails, because ABAP sends the whole unit again. It also
fails a unit that has no calls, that names a function no handler is registered for, or whose
`SDATA` lengths do not add up. Every length in `SDATA` comes from the peer and is checked
before use.

**`BGRFC_CHECK_UNIT_STATE_SERVER`** [ASSUMED] for this direction: ABAP was not seen asking a
registered server for a unit's state. `RfcServer` reads `UNIT_ID` and `UNIT_KIND` as the
client sends them, and answers `STATE` with the integers of the client's state table.

**Setting up the sender** (what the capture needed on the ABAP side). A registered TCP/IP
destination (type `T`) with the bgRFC protocol selected; with the classic qRFC protocol,
`CL_BGRFC_DESTINATION_OUTBOUND=>CREATE` refuses the destination as not registered. The
destination registered for outbound bgRFC (`CL_BGRFC_REG_DEST`, SBGRFCCONF) and a supervisor
destination (`BGRFC_SET_SUPERVISOR_DEST`). basXML was on.

---

## Known Gaps

### The `0x5001` block of 2026-07-05
A capture on 2026-07-05 of a tRFC the SAP system sent to a registered server showed a
compact block encoding: CHAR values as `0x43 [len] 0x80 [value]`, the TID fields at offsets
504 / 515 / 522 / 533 as 8 + 4 + 8 + 4 uppercase hex characters, `ARFCFNAM` at 1716, and an
unexplained 11-byte preamble `34 08 0c 00 00 4c 07 00 00 f1 31` at offset 14. The captures
of 2026-11-27 (Inbound tRFC, above) show no such block, with basXML on or off. The block is the
newer column-wise parameter serialization (tags `0x5000`/`0x5001`), not the classic or basXML
one; which destination setting selects it was not captured. `RfcServer` no longer reads a TID
from it, and its parser of the block's CHAR values (`server._extract_5001_params`) remains
**[ASSUMED]**: a capture with that serialization selected would settle the layout.

### Several calls in one LUW (not in the public API)

The wire format carries any number of calls (fixture `trfc`: two). `call_transactional`
sends one per TID.

### tRFC over WebSocket RFC
No capture. `call_transactional` raises `NotImplementedError` on a WebSocket connection.

### Backend tables (A4H, kernel 793, observed 2026-09-04)

Which tables hold what, read off a live system rather than inferred from their names. This
matters because the obvious guess is wrong in a way that fails silently:

| Table | Holds |
|-------|-------|
| `BGRFC_CUST_SUPER` | supervisor destination; empty on kernel 916, where directly submitted units still ran inline (2026-11-26) |
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
