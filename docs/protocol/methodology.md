# RE Methodology: Reverse Engineering the SAP RFC Protocol

## Overview

This document describes the reverse engineering (RE) workflow used to derive the SAP RFC wire protocol specification for the `saprfclib` project. It is intended for future contributors extending the protocol documentation, and for validation of documented findings.

---

## RE Sources (Ranked by Confidence)

| Source | Confidence | Usage |
|--------|------------|-------|
| Live Wireshark capture (pcap) | **HIGHEST** | Ground truth for wire bytes; overrides all other sources |
| SAP SDK headers (`sapnwrfc.h`, `sapucrfc.h`, `sapdecf.h`) | **HIGH** | Type definitions, enum values, field descriptions |
| Binary Ninja decompilation of `libsapnwrfc.so` | **HIGH** | Confirms header assumptions; reveals byte-order at call sites |
| `pyrfc` behavior (black-box observation) | **MEDIUM** | Reveals what SAP accepts; does not reveal exact wire bytes |
| Protocol inference from traffic patterns | **LOW** | Useful for hypothesis generation; requires confirmation |

**Rule:** Any field documented as CONFIRMED must have a live capture citation or BN call-site reference. Fields marked `[ASSUMED]` are hypotheses pending confirmation.

---

## Toolchain

### Live Traffic Capture

```bash
# Capture SAP RFC traffic (port = 3300 + sysnr)
bash captures/capture.sh

# Manual capture (when tshark/dumpcap capabilities unavailable)
# Use Wireshark GUI → capture on 'any' interface, filter: tcp port 3300
```

**Critical discovery:** pyrfc wraps `libsapnwrfc.so` (native C library). The C library calls `socket()` directly — Python socket monkey-patching is ineffective. Use Wireshark/tshark at the OS interface level, not Python-level interception.

**Port:** SAP NW RFC SDK connects to **3300 + sysnr** (Gateway port), NOT 3200 (Dispatcher). Captures on port 3200 will yield 0 packets.

### pcap Analysis

```python
import subprocess, struct

# List frames
result = subprocess.run([
    "tshark", "-r", "captures/stfc_connection.pcapng",
    "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "tcp.len", "-e", "tcp.payload"
], capture_output=True, text=True)

# Parse NI frame from raw TCP payload
raw = bytes.fromhex(tcp_payload_hex)
ni_len = struct.unpack_from(">I", raw, 0)[0]
payload = raw[4:4+ni_len]

# Parse TLV stream (starts at payload offset 80)
# [tag 2B BE][len 2B BE][data][close_tag 2B BE]
# Extended: [tag 2B][0xFFFF][len 4B BE][data][close_tag 2B]
# Terminated by: tag=0xFFFF len=0
```

### Binary Ninja (BN) Decompilation

```python
# Via MCP tools (when BN MCP server running):
mcp__binary_ninja_mcp__select_binary(path="sap-rfc-sdk/nwrfcsdk/lib/libsapnwrfc.so")
mcp__binary_ninja_mcp__decompile_function(address=0x8d35f)  # RfcInvoke entry
mcp__binary_ninja_mcp__get_il(address=0x8d35f, il_type="hlil")
```

BN is used to confirm byte-order at type serialization call sites and to verify TLV encoding paths.

---

## Protocol Discovery Process

### Step 1: Capture Known Traffic

Use `pyrfc` (the reference implementation) to make well-known calls and capture the traffic:

```python
conn.call("STFC_CONNECTION", REQUTEXT="saprfc_capture_test")
conn.call("STFC_STRUCTURE", IMPORTSTRUCT={...all scalar types...})
```

`STFC_CONNECTION` gives a minimal frame (CHAR params only). `STFC_STRUCTURE` (RFCTEST struct) gives INT1, INT2, INT4, FLOAT, CHAR, DATE, TIME all in one struct.

### Step 2: Identify Frame Boundaries

Every TCP payload is an NI frame:
- Bytes 0-3: NI length (BE uint32, excludes 4-byte header)
- Bytes 4+: payload

For RFC data frames (handshake phase 3 + function calls):
- Payload offset 0-75: 76-byte GW/APPC header
- Payload offset 76-79: RFC marker (0xFFFF0001 = client, 0x00000001 = server)
- Payload offset 80+: TLV stream (or COM_HEAD + TLV for logon frame only)

### Step 3: Parse TLV Stream

Each TLV record has:
```
tag (2B BE) | len (2B BE, or 0xFFFF for extended) | [ext_len 4B BE] | data | close_tag (2B BE)
```

The TLV stream ends when `tag == 0xFFFF and len == 0`.

Common structural tags:
- `0x0502 len=0` = call-start
- `0x0512 len=0` = parameter section start
- `0x0102` = function name (UTF-16LE)
- `0x0201` = parameter name (UTF-16LE)
- `0x0203` = parameter value (UTF-16LE or binary)
- `0x0205` = parameter name in response
- `0xFFFF len=0` = terminator

### Step 4: Decode Parameter Values

Parameter values (`0x0203` / `0x0204`) contain the serialized ABAP type:
- CHAR(N): `N×2` bytes UTF-16LE, space-padded
- DATE: 16 bytes UTF-16LE (YYYYMMDD)
- TIME: 12 bytes UTF-16LE (HHMMSS)
- INT4: 4 bytes **little-endian** signed int
- INT2: 2 bytes **little-endian** signed int
- INT1: 1 byte unsigned int
- FLOAT: 8 bytes IEEE 754 double **little-endian**

Key pitfall: **ABAP integers are little-endian** (x86 native) while **NI headers are big-endian** (network byte order). Don't confuse the two.

### Step 5: Create Golden Fixtures

For each confirmed frame:
1. Extract raw bytes from pcap → `tests/golden/{category}/{name}.bin`
2. Write field annotations JSON → `tests/golden/{category}/{name}.json`
3. JSON schema requires: `message_type`, `ni_header_length`, `field_annotations[]`, `expected_parse`, `capture_source`
4. D-12 check: `sum(annotation.length) == len(bin_file)` — every byte must be annotated

Tests in `tests/golden/{category}/test_*.py` verify D-12 on every fixture load.

---

## Known Pitfalls

| Pitfall | Detail |
|---------|--------|
| Wrong port | pyrfc connects to **3300+sysnr** (Gateway), not 3200 (Dispatcher). Filter `tcp port 3300`. |
| Python socket interception | `libsapnwrfc.so` calls C `socket()` directly. Python `socket.socket` subclassing doesn't intercept it. Use Wireshark at OS level. |
| tshark vs dumpcap capabilities | `tshark` uses `dumpcap` internally. Setting `cap_net_raw` on `tshark` binary alone is insufficient — must set on `dumpcap` binary or use `sudo`. |
| COM_HEAD only in logon frame | `D9C6C3F0F0F0F0F0F0F0F0F0` (EBCDIC "RFC000000000") appears ONLY in the logon frame (frame 14). Function call frames start TLV directly at offset 80 — no COM_HEAD. |
| INT byte order | NI length headers are big-endian. ABAP INT2/INT4 inside struct values are **little-endian**. |
| CHAR width vs byte width | CHAR(N) is N characters = N×2 bytes in UTF-16LE mode. `field_length` in descriptors is in characters. Off-by-2x is common. |
| UTF-16 BOM | Use explicit `utf-16-le` codec, never bare `utf-16` (which emits/reads BOM). The SAP wire format has no BOM. |
| Metadata prefetch frames | pyrfc auto-calls `RFC_GET_FUNCTION_INTERFACE` and `DDIF_FIELDINFO_GET` before user-visible calls. The actual `STFC_STRUCTURE` call is frame 35, not frame 19. Always count frames carefully. |
| STFC_STRUCTURE has 264-byte struct | The RFCTEST struct blob is 264 bytes with alignment padding. The last 200 bytes are CHAR-field space-padding. Actual scalar data is in offsets 0-63. |

---

## RFCTEST Structure Layout (Confirmed from Live Capture)

From `STFC_STRUCTURE IMPORTSTRUCT` in frame 35 (264 bytes total):

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
28      8     [unk]    —           —               00 00 00 00 20 00 20 00
36      12    TIME     RFCTIME     "120000"        31 00 32 00 30 00 30 00 30 00 30 00
48      16    DATE     RFCDATE     "20260626"      32 00 30 00 32 00 36 00 30 00 36 00 32 00 36 00
64      200   [chars]  —           spaces          20 00 repeated (space UTF-16LE)
```

Offsets 28-35 contain unknown fields (possibly additional RFCTEST fields not set in the test call).

---

## RE Session Log

| Date | Session | Deliverable |
|------|---------|-------------|
| 2026-06-26 | BN decompilation of `NiIWrite`/`NiIRead` | NI header = 4B BE uint32 (confirmed) |
| 2026-06-26 | BN decompilation of GW header path | 76-byte APPC/GW header (confirmed) |
| 2026-06-26 | Live Wireshark capture (manual, 40 frames) | All Gate A+C fields confirmed |
| 2026-06-26 | STFC_STRUCTURE frame 35 analysis | RFCTEST struct layout, INT/FLOAT byte order confirmed |

---

*Document created: 2026-06-26*
*See also: [framing.md](framing.md), [serialization.md](serialization.md), [handshake.md](handshake.md)*
