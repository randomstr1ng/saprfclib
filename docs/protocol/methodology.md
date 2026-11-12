# Protocol Analysis Methodology

## Overview

This document describes how the SAP RFC wire protocol specification in these pages was
derived, and how to extend it. It is written for contributors adding protocol coverage,
and for anyone who wants to check a documented claim rather than take it on trust.

The protocol is not publicly specified. Everything here was established by observing
traffic between systems the authors operate, for the purpose of interoperating with SAP
systems the operator is licensed to use. No SAP source, headers, or binaries are
reproduced in this repository — see [NOTICE](https://github.com/randomstr1ng/saprfclib/blob/main/NOTICE).

---

## Evidence Tiers

Every documented fact names its source. The source is part of the claim: a byte layout
marked `[ASSUMED]` is a hypothesis, not a specification.

| Tier | Source | Weight | What it establishes |
|------|--------|--------|---------------------|
| **Live capture** | Wireshark/tshark pcap of real traffic | **HIGHEST** | Ground truth for wire bytes. Overrides every other source, including this document. |
| **Golden fixture** | A capture committed under `tests/golden/` | **HIGHEST** | Same as above, replayable in CI. |
| **Behavioural probe** | What a live server accepts or rejects | **MEDIUM** | Semantics and validity ranges; not exact bytes. |
| **Inference** | Extrapolation from a confirmed neighbouring field | **LOW** | Hypothesis only. Must be labelled `[ASSUMED]`. |

**Rule:** a fact without a label is established and cites its live capture, golden fixture or
probe right where it is stated. A fact that rests on inference is labelled `[ASSUMED]` and says
what would settle it. What is not known at all goes under the page's "Known Gaps". There is
no "confirmed" label: an unlabelled fact is one, and a gap that is closed leaves the gap list
and moves, with its evidence, to the section it belongs to. No value is documented without a
stated source — see [CLAUDE.md](https://github.com/randomstr1ng/saprfclib/blob/main/CLAUDE.md)
for why this is enforced rather than encouraged.

---

## Capturing Traffic

RFC rides on plain TCP. The gateway port is **3300 + sysnr** — not 3200, which is the
dispatcher. Captures filtered on 3200 yield zero RFC packets.

```bash
# Capture RFC traffic to a system with sysnr=00
sudo tshark -i any -f "tcp port 3300" -w rfc_session.pcapng
```

Capture at the OS interface level. Intercepting inside Python does not work against
SAP's own client: it is a native library that calls `socket()` directly, so replacing
`socket.socket` in the interpreter sees nothing. This also applies to `saprfclib`'s own
traffic if you want a comparison capture — use the same interface-level tooling for
both so the two are directly diffable.

!!! note "tshark capabilities"
    `tshark` shells out to `dumpcap`. Granting `cap_net_raw` to the `tshark` binary
    alone is not enough — set it on `dumpcap`, or capture with `sudo`.

---

## Analysing a Capture

```python
import subprocess, struct

# List frames with their raw TCP payloads
result = subprocess.run([
    "tshark", "-r", "rfc_session.pcapng",
    "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "tcp.len", "-e", "tcp.payload"
], capture_output=True, text=True)

# Every TCP payload is an NI frame
raw = bytes.fromhex(tcp_payload_hex)
ni_len = struct.unpack_from(">I", raw, 0)[0]   # big-endian, excludes the 4-byte header
payload = raw[4:4 + ni_len]

# TLV stream begins at payload offset 80
# [tag 2B BE][len 2B BE][data][close_tag 2B BE]
# Extended:  [tag 2B BE][0xFFFF][len 4B BE][data][close_tag 2B BE]
# Terminated by: tag=0xFFFF, len=0
```

---

## Discovery Process

### Step 1 — Capture known traffic

Drive well-known function modules so the payload content is predictable, and capture
the result:

```python
conn.call("STFC_CONNECTION", REQUTEXT="saprfc_capture_test")
conn.call("STFC_STRUCTURE", IMPORTSTRUCT={...all scalar types...})
```

`STFC_CONNECTION` produces a minimal frame — CHAR parameters only. `STFC_STRUCTURE`
carries the RFCTEST structure, which packs INT1, INT2, INT4, FLOAT, CHAR, DATE and TIME
into a single value, making it the most efficient single call for type work.

Using a known-good client for the capture and `saprfclib` for a second capture of the
same call gives a byte-level diff that localises a defect immediately.

### Step 2 — Identify frame boundaries

Every TCP payload is one NI frame:

- bytes 0–3: NI length, big-endian uint32, excluding the 4-byte header
- bytes 4+: payload

For RFC data frames (handshake phase 3 onward, and all function calls):

- payload offset 0–75: 76-byte gateway/APPC header
- payload offset 76–79: RFC marker — `0xFFFF0001` client, `0x00000001` server
- payload offset 80+: TLV stream (the logon frame additionally carries COM_HEAD here)

### Step 3 — Parse the TLV stream

```
tag (2B BE) | len (2B BE, or 0xFFFF for extended) | [ext_len 4B BE] | data | close_tag (2B BE)
```

The stream ends at `tag == 0xFFFF and len == 0`.

Structural tags seen in every call:

| Tag | Meaning |
|-----|---------|
| `0x0502` len=0 | Call start |
| `0x0512` len=0 | Parameter section start |
| `0x0102` | Function name (UTF-16LE) |
| `0x0201` | Parameter name (UTF-16LE) |
| `0x0203` | Parameter value (UTF-16LE or binary) |
| `0x0205` | Declaration of a parameter the server should return (EXPORTING/CHANGING/TABLES), sent in the request; name UTF-16LE (`_TAG_EXPORT_DECL` in `src/saprfclib/invoke.py`, framing.md) |
| `0xFFFF` len=0 | Terminator |

### Step 4 — Decode parameter values

Parameter value records (`0x0203`) hold the serialized ABAP value:

| Type | Wire form |
|------|-----------|
| CHAR(N) | N×2 bytes UTF-16LE, space-padded |
| DATE | 16 bytes UTF-16LE (`YYYYMMDD`) |
| TIME | 12 bytes UTF-16LE (`HHMMSS`) |
| INT4 | 4 bytes **little-endian** signed |
| INT2 | 2 bytes **little-endian** signed |
| INT1 | 1 byte unsigned |
| FLOAT | 8 bytes IEEE 754 double, **little-endian** |

The trap: **ABAP scalars are little-endian while NI headers are big-endian.** Both
appear in the same frame, a few bytes apart.

### Step 5 — Commit a golden fixture

For each captured frame:

1. Extract the raw bytes to `tests/golden/{category}/{name}.bin`.
2. Write the field annotations to `tests/golden/{category}/{name}.json`, including
   `message_type`, `field_annotations[]`, `expected_parse`, `capture_source` and
   `evidence` — the keys `load_fixture` in `tests/conftest.py` requires — plus
   `ni_header_length` when the NI header is not the default 4 bytes.
3. Satisfy the **zero-unknowns rule**: `sum(annotation.length) == len(bin_file)`. Every
   byte in a fixture must be accounted for. A byte nobody can explain is an open
   question, not a detail.

The rule is enforced only for handshake fixtures (`tests/golden/handshake/test_handshake.py`);
`load_fixture` does not check it, and some framing captures (`stfc_changing_*`,
`stfc_structure_*`, `rfc_read_table_request`/`_response`) have no `.json` at all. A new fixture
is checked against the rule in review, not by CI.

Sanitising a fixture — removing a real hostname or credential — must preserve the
original byte length, or every offset after the substitution becomes wrong. See the
substitution note in `tests/test_router.py` for the pattern.

---

## Known Pitfalls

| Pitfall | Detail |
|---------|--------|
| Wrong port | RFC connects to **3300 + sysnr** (gateway), not 3200 (dispatcher). Filter `tcp port 3300`. |
| Python-level interception | SAP's client is native and calls `socket()` directly; subclassing `socket.socket` intercepts nothing. Capture at the OS level. |
| tshark vs dumpcap capabilities | `cap_net_raw` must be set on `dumpcap`, not just `tshark`. |
| COM_HEAD only in the logon frame | `D9C6C3F0F0F0F0F0F0F0F0F0` (EBCDIC `RFC000000000`) appears **only** in the logon frame. Function-call frames start the TLV stream directly at offset 80. |
| INT byte order | NI length headers are big-endian; ABAP INT2/INT4 inside values are little-endian. |
| CHAR width vs byte width | CHAR(N) is N *characters* = N×2 bytes in UTF-16LE. `field_length` in descriptors is in characters. The off-by-2× is the most common bug in this codebase. |
| UTF-16 BOM | Use explicit `utf-16-le`; never bare `utf-16`, which emits and consumes a BOM. The wire format has none. |
| Metadata prefetch frames | A client auto-issues `RFC_GET_FUNCTION_INTERFACE` and `DDIF_FIELDINFO_GET` before the user's call. The call you are looking for is not the first RFC frame in the capture — count carefully. |
| RFCTEST is 264 bytes | The structure blob is 264 bytes including alignment padding. Offsets 0–63 hold the scalar fields; 64–263 hold character data (see the layout below). |

---

## RFCTEST Structure Layout

From a live `STFC_STRUCTURE IMPORTSTRUCT` capture (2026-06-26), 264 bytes. The committed
fixture `tests/golden/framing/stfc_structure_request.bin` is a different call with the same
offsets (other values: FLOAT 1.5, INT2 2, INT4 4, `data1…` at offset 64):

```
Offset  Size  Type     Field       Value (sent)    Wire bytes
0       8     FLOAT    RFCFLOAT    3.14159         6e 86 1b f0 f9 21 09 40 (LE double)
8       2     CHAR(1)  RFCCHAR1    "A"             41 00 (UTF-16LE)
10      2     INT2     RFCINT2     256             00 01 (LE = 0x0100)
12      1     INT1     RFCINT1     1               01
13      1     pad      —           —               00
14      8     CHAR(4)  RFCCHAR4    "ABCD"          41 00 42 00 43 00 44 00
22      2     pad      —           —               00 00
24      4     INT4     RFCINT4     65536           00 00 01 00 (LE = 0x00010000)
28      8     [ASSUMED] HEX3+pad+CHAR(2)  —      00 00 00 00 20 00 20 00
36      12    TIME     RFCTIME     "120000"        31 00 32 00 30 00 30 00 30 00 30 00
48      16    DATE     RFCDATE     "20260626"      32 00 30 00 32 00 36 00 30 00 36 00 32 00 36 00
64      200   [ASSUMED] RFCDATA1/2  spaces       20 00 repeated (space UTF-16LE)
```

**[ASSUMED]** Offsets 28–35 are `RFCHEX3` (3 bytes, zero), one pad byte and `RFCCHAR2`
(2 blank characters), and 64–263 are `RFCDATA1`/`RFCDATA2` as two 50-character fields. The
field names are ones the integration tests send to `STFC_STRUCTURE`
(`tests/test_phase05_integration.py`, `tests/test_phase04_integration.py`), and the bytes
match those widths; the committed fixture carries `data1…` at offset 64. The positions are
inferred from the widths, not read from metadata. A `DDIF_FIELDINFO_GET` reply for `RFCTEST`,
or a capture with `RFCHEX3` set, would settle it.

---

*See also: [Framing](framing.md), [Serialization](serialization.md), [Handshake](handshake.md).*
