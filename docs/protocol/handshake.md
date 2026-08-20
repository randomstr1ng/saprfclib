# SAP RFC Logon Handshake Protocol

## Status

**CONFIRMED — live Wireshark capture 2026-06-26 (SAP A4H, sysnr=00, port=3300)**

Gate C: CLOSED. Full logon sequence documented from frames 4-15.

---

## Overview

SAP RFC logon over TCP (direct `ashost` mode) consists of three phases before any function calls:

1. **NI Version Exchange** — codepage negotiation (2 round trips)
2. **GW Connect** — Gateway-layer connection establishment (3+ frames)
3. **RFC Logon TLV** — RFC-layer credential exchange (1 round trip)

```
TCP SYN/SYN-ACK/ACK  [frames 1-3]
│
├── Phase 1: NI Version Exchange
│   ├── frame 4:  C→S  NI_VERSION (68B)  — propose codepage '1100'
│   └── frame 6:  S→C  NI_VERSION (68B)  — select codepage '4103' (UTF-16LE)
│
├── Phase 2: GW Connect
│   ├── frame 8:  C→S  GW_CONNECT_REQUEST (457B, type 0x0601)  — program/host info
│   ├── frame 9:  S→C  GW_CONNECT_RESPONSE (84B, type 0x0601)  — assign handle '75568442'
│   ├── frame 10: C→S  GW_INFO (228B, type 0x060F)             — network info
│   ├── frame 11: C→S  GW_DONE (84B, type 0x0605)              — GW handshake complete
│   └── frame 13: S→C  GW_DONE (84B, type 0x0605)              — confirm, codepage '4103'
│
└── Phase 3: RFC Logon TLV
    ├── frame 14: C→S  RFC_LOGON (341B, type 0x06CB)  — COM_HEAD + credentials TLV
    └── frame 15: S→C  RFC_LOGON_RESP (736B, type 0x06CB)  — system info TLV
```

---

## Phase 1: NI Version Exchange

### Wire Format (68 bytes)

```
[0-3]   ni_length       4B  BE uint32 = 64
[4-5]   msg_type        2B  0x0203 (NI version frame)
[6-9]   client_ip       4B  IPv4 of client (10.20.30.65 = 0x0a141e41)
[10-13] zeros           4B
[14-21] program_name    8B  NUL-terminated ASCII (e.g. "python3\x00")
[22-23] zeros           2B
[24-27] codepage        4B  ASCII codepage string (e.g. "1100" or "4103")
[28-31] zeros           4B
[32-33] version_flags   2B  0x0006 (client) / 0x000f (server)
[34-43] hostname        10B space-padded ASCII (e.g. "titan     ")
[44-53] program_padded  10B space-padded ASCII (e.g. "python3   ")
[54-55] rfc_hint        2B  0x06cb (client) / 0x06fb (server)
[56-57] unicode_capable 2B  0xffff
[58-67] zeros           10B
```

### Codepage Negotiation

The critical field is **offset 24 (4B ASCII):**
- Client proposes `"1100"` — Latin-1 / non-Unicode
- Server responds with `"4103"` — **UTF-16LE Unicode mode**

After codepage `4103` is selected, all string data in all subsequent RFC frames uses **UTF-16LE** encoding. This is the `SAP_UC = char16_t` wire encoding documented in `sapucrfc.h`.

**Implementation note:** Parse the server's NI_VERSION response and store the negotiated codepage. If codepage is `4103`, use `utf-16-le` for all SAP_UC field encoding. Other known codepages (e.g. `1100` = Latin-1) would use single-byte encoding — but in practice SAP systems enforce Unicode mode for NW RFC SDK connections.

### Fixture

- `tests/golden/handshake/ni_version_request.bin` — frame 4 (68 bytes)
- `tests/golden/handshake/ni_version_response.bin` — frame 6 (68 bytes)

---

## Phase 2: GW Connect

### GW Message Types

| Type | Hex | Description |
|------|-----|-------------|
| GW_CONNECT | `06 01` | Connect request/response |
| GW_INFO    | `06 0F` | Network/routing information |
| GW_DONE    | `06 05` | Handshake complete |

All GW frames share the same 4-byte NI header followed by an 80-byte GW body (for the standard frames; GW_CONNECT_REQUEST from client is 457 bytes with routing info).

### GW Frame Structure (80-byte body frames)

```
[0-3]   ni_length       4B  BE uint32 (= body length, excludes header)
[4-5]   gw_msg_class    2B  e.g. 0x0601, 0x0605
[6-7]   gw_protocol_ver 2B  0x0200 (version 2.0)
[8-11]  gw_flags        4B  0xffff0000 + session state
[12-31] gw_session_info 20B server session state [UNKNOWN layout]
[32-39] connection_handle 8B  ASCII decimal, e.g. "75568442" — assigned by server in frame 9
[40-71] padding/fields  32B  program area, zeros
[72-75] codepage        4B  ASCII codepage "4103" (in server GW_DONE only; client leaves zeros)
[76-79] tail            4B  0x00000001
```

### Connection Handle

The connection handle (`"75568442"` in this capture) is:
- Assigned by the server in the GW_CONNECT_RESPONSE (frame 9)
- Inserted at **offset 32** of every subsequent GW/RFC header
- An 8-byte ASCII decimal string (varies per session)

### Sequence

1. Client sends GW_CONNECT_REQUEST (type 0x0601, 457 bytes) containing:
   - RFC program name ("NWRFC"), server host prefix ("10.20.30"), program ID ("sapdp00")
   - CPIC identifier string
   - Client hostname ("randomstr1ng"), client IP ("10.20.30.15")

2. Server sends GW_CONNECT_RESPONSE (type 0x0601, 84 bytes) containing:
   - **Assigned connection handle at offset 32** ("75568442")
   - Program area echo

3. Client sends GW_INFO (type 0x060F, 228 bytes):
   - Additional network routing info [UNKNOWN layout]
   - Connection handle at offset 32

4. Client sends GW_DONE (type 0x0605, 84 bytes):
   - Connection handle at offset 32
   - Codepage field (offsets 72-75) is all zeros from client

5. Server sends GW_DONE (type 0x0605, 84 bytes):
   - Connection handle confirmed
   - **Codepage "4103" written at offset 72** — second confirmation of UTF-16LE mode

### Fixtures

- `tests/golden/handshake/gw_connect_response.bin` — frame 9 (84 bytes)
- `tests/golden/handshake/gw_done_client.bin` — frame 11 (84 bytes)
- `tests/golden/handshake/gw_done_server.bin` — frame 13 (84 bytes)

GW_CONNECT_REQUEST (frame 8) is NOT included as a fixture — it contains routing info including client hostname (PII).

---

## Phase 3: RFC Logon TLV

After the GW handshake completes, the client sends the RFC-layer logon frame (type 0x06CB — the same GW type used for all subsequent RFC data frames).

### Wire Structure

```
[0-3]   ni_length       4B  BE uint32 = 337 (0x00000151)
[4-79]  gw_header       76B  Same GW header structure as all RFC data frames
[80-83] rfc_marker      4B  0xffff0001 (client request)
[84-95] com_head        12B  D9C6C3F0F0F0F0F0F0F0F0F0 = EBCDIC "RFC000000000"
                             *** ONLY present in logon frame, NOT in subsequent calls ***
[96-336] logon_tlv      241B  TLV records with credentials
```

### Logon TLV Tags (frame 14)

| Tag | Length | Value | Description |
|-----|--------|-------|-------------|
| 0x0101 | 8 | binary | Session flags / capability bits |
| 0x0103 | 4 | binary | Protocol version bits |
| 0x0106 | 11 | binary | Codepage negotiation data |
| 0x0514 | 16 | binary | Session token (16 bytes) |
| 0x0114 | 3 | ASCII "001" | SAP client number |
| 0x0111 | 9 | ASCII "Developer" | SAP username |
| 0x0117 | 17 | binary | Scrambled password: `seed(4B rand_r) + ab_scramble(pw, seed)` — see OQ-C01 (RESOLVED) |
| 0x0115 | 1 | ASCII "E" | Logon language |
| 0x0501 | 1 | 0x01 | Flag [UNKNOWN] |
| 0x0007 | 9 | ASCII "127.0.1.1" | Client IP address |
| 0x0011 | 1 | ASCII "E" | Language (again) |
| 0x0012 | 3 | ASCII "754" | RFC protocol version |
| 0x0013 | 3 | ASCII "754" | Server RFC version |
| 0x0008 | 5 | ASCII "titan" | Client hostname |
| 0x0006 | 9 | ASCII "\<unknown\>" | Client program/transaction |
| 0x0130 | 7 | ASCII "python3" | Client program name |
| 0x0502 | 0 | — | Call-start marker |
| 0x000b | 3 | ASCII "754" | RFC version (in call context) |
| 0x0102 | 7 | ASCII "RFCPING" | Initial "function" — logon probe |
| 0xFFFF | 0 | — | TLV stream terminator |

**Note on RFCPING:** The logon TLV ends with a call to `RFCPING`. This is NOT an application function call — it is the SAP RFC SDK's logon probe. The server processes the credentials and returns the logon response (frame 15). `RFCPING` means "validate this connection" at the protocol level.

**Note on COM_HEAD:** Only present in this logon frame. All subsequent RFC call frames (STFC_CONNECTION, STFC_STRUCTURE, etc.) have NO COM_HEAD — the TLV stream starts directly at NI payload offset 80.

### Server Logon Response TLV Tags (frame 15)

| Tag | Length | Value | Description |
|-----|--------|-------|-------------|
| 0x0450 | 6 | "A4H" | SAP System ID (SID) |
| 0x0451 | 20 | "DEMOSYSTEM" | System description |
| 0x0452 | 4 | "00" | System number |
| 0x0453 | 20 | "vhcala4hci" | Application server hostname |
| 0x0012 | 8 | "758" | SAP release number |
| 0x0013 | 8 | "793" | Kernel version |
| 0x0008 | 34 | "vhcala4hci_A4H_00" | Server instance name |
| 0x0150 | 24 | "DEVELOPER" | Logged-in user (normalized to upper) |
| 0x0151 | 6 | "001" | Client number |
| 0x0152 | 2 | "E" | Language |
| 0x0016 | 8 | "1100" | Client codepage as reported |
| 0x0420 | 4 | 0x00000000 | RFC return code (0 = success) |
| 0x0514 | 16 | binary | Session token |
| 0xFFFF | 0 | — | TLV stream terminator |

### Fixture

The logon request and response fixtures (frames 14 and 15) are stored in `tests/golden/framing/`:
- `tests/golden/framing/logon_request.bin` + `.json`

The response (frame 15) is not yet extracted as a standalone fixture — add as needed.

---

## Password scrambling (0x0117) — OQ-C01 RESOLVED

The 17-byte 0x0117 record is **not a cryptographic hash**. SAP scrambles the password
with the classic reversible **`ab_scramble`** byte cipher and prepends a 4-byte
client-generated random seed. Derived from Binary Ninja / objdump decompilation of
`libsapnwrfc.so` (`binja_ref`s in
[bn-passwordhash-notes.md](../../.planning/phases/04-reverse-engineering-spike-protocol-spec/bn-passwordhash-notes.md)):

```
0x0117 value (17 bytes for the captured 13-char password):

  [ seed: 4 bytes ]  [ ab_scramble(password_bytes, seed) : N bytes ]
    rand_r(time())     N = len(password) in the password codepage
  total = 4 + N

ab_scramble(buf, len, seed):              # symmetric XOR stream; its own inverse
    k  = (((seed >> 5) ^ (seed*2)) ^ seed) & 0x3f
    ck = 0xffffffff
    for i in range(len):
        ks   = (ck * i) & 0xffffffff
        kb   = (ks ^ kt[k]) & 0xff
        buf[i] ^= kb
        k  = (k + 1) & 0x3f
        ck = (ck + seed) & 0xffffffff

kt (64-byte key table, .rodata @ 0x647c20):
    f0ed53b83244f1f876c67959fd4f13a2
    c15195ec5483c234774943a27de26596
    5e5398789a17a33cd383a8b829fbdca5
    55d7027784 13acddf9b8311 6610e6dfa   (whitespace cosmetic)
```

Provenance (BN/nm addresses; BN = nm + 0x400000):
- `writeRfcSessionLogon` 0x5543b8 — emits TLV order 0x114, 0x111, …, **0x117** (writeRfcData), 0x115
- `scrambleChars` 0x55176a — `time()`→`ThrRand`(=`rand_r`)→writes seed→`ab_scramble`, returns `len+4`
- `ab_scramble` 0x7099e6 — the cipher above
- `unscramblePassword` 0x5529be — inverse: reads seed from first 4 bytes, re-runs `ab_scramble`

**Salt freshness (T-04-SALT):** the seed is a fresh client `rand_r(time())` per scramble —
there is NO server-supplied nonce. The 0x0514 session token and codepage tags do NOT feed it.

**Residual GAP (live truth-check, Plan 04-01 Task 3):** scrambleChars branches on the
password codepage (`conn+0xdfc`); a 13-char ASCII password producing exactly 13 scrambled
bytes implies the **single-byte passthrough** codepage was used for the password (even
though the session negotiated 4103/UTF-16LE for all other strings). The implementation
uses single-byte; a live logon reaching READY (0x0420 == 0) is the byte-for-byte proof.

---

## Key Protocol Facts (Gate C Findings)

| Finding | Evidence | Confidence |
|---------|----------|------------|
| Codepage negotiated in NI_VERSION at offset 24 | Frame 4 (proposes "1100") + Frame 6 (selects "4103") | HIGH — live capture |
| Codepage 4103 = UTF-16LE (Unicode mode) | sapucrfc.h + codepage 4103 confirmation in frames 6 and 13 | HIGH |
| COM_HEAD only in logon frame | Frames 14 (has COM_HEAD), 19/21/24/35 (no COM_HEAD) | HIGH — live capture |
| Connection handle = 8-byte ASCII decimal | Frame 9 assigns "75568442", used in all subsequent frames | HIGH — live capture |
| RFC logon TLV uses 0x0114/0x0111/0x0117 for client/user/password | Frame 14 TLV parse | HIGH — live capture |
| Password field is tag 0x0117, 17 bytes | Frame 14 TLV parse | HIGH — live capture |
| 0x0117 = `seed(4B) + ab_scramble(pw, seed)`, NOT a hash (reversible cipher) | BN: writeRfcSessionLogon 0x5543b8 → scrambleChars 0x55176a → ab_scramble 0x7099e6; inverse unscramblePassword 0x5529be | HIGH — BN decompilation (live byte-for-byte pending Task 3) |
| Server response includes SID (0x0450), release (0x0012), user (0x0150) | Frame 15 TLV parse | HIGH — live capture |
| Logon always calls RFCPING as probe (tag 0x0102 in logon TLV) | Frame 14 | HIGH — live capture |

---

## Open Questions

| # | Question | Urgency | Notes |
|---|----------|---------|-------|
| ~~OQ-C01~~ **RESOLVED** | ~~Password hash format~~ | — | **It is NOT a hash.** Tag 0x0117 = SAP's reversible `ab_scramble` byte cipher: `value = seed(4B) + ab_scramble(password, seed)`. `seed` is a client-local `rand_r(time())` nonce (NO server salt). 17B = 4 (seed) + 13 (password bytes). Algorithm + 64-byte key table `kt`@0x647c20 fully decompiled. See [bn-passwordhash-notes.md](../../.planning/phases/04-reverse-engineering-spike-protocol-spec/bn-passwordhash-notes.md) and §"Password scrambling (0x0117)" below. **Residual:** codepage of scrambled bytes (single-byte passthrough inferred from 17B length) is byte-for-byte confirmed only by the live logon truth-check (Plan 04-01 Task 3). |
| OQ-C02 | Tag 0x0106 (11 bytes): codepage negotiation details | MEDIUM | Appears in both request and response; binary content unclear |
| OQ-C03 | Tag 0x0101 (8 bytes): capability flags bit layout | MEDIUM | Differs between request (client) and response (server) |
| OQ-C04 | GW_INFO (type 0x060F) layout | LOW | Frame 10 contains network routing info; not needed for basic logon implementation |
| OQ-C05 | SNC/Kerberos logon path | LOW | Different tag set; defer to Phase 2+ SNC implementation |

---

## Implementation Notes

To implement the logon handshake in `saprfclib`:

1. **Phase 1 — NI Version:**
   - Send NI_VERSION frame with `msg_type=0x0203`, client IP, program name, proposed codepage "1100"
   - Read server NI_VERSION response; extract codepage at offset 24
   - If codepage == "4103": set `unicode_mode=True`, all subsequent strings use `utf-16-le`

2. **Phase 2 — GW Connect:**
   - Send GW_CONNECT_REQUEST (type 0x0601) with program area, CPIC ID, client info
   - Read server response; extract connection handle from offset 32
   - Send GW_INFO (type 0x060F) with network info
   - Send GW_DONE (type 0x0605)
   - Read server GW_DONE; verify codepage echo

3. **Phase 3 — RFC Logon TLV:**
   - Construct GW header with connection handle at offset 32
   - Write RFC_MARKER = 0xffff0001
   - Write COM_HEAD = D9C6C3F0F0F0F0F0F0F0F0F0
   - Write logon TLV records (tags 0x0114, 0x0111, 0x0117, 0x0115, etc.)
   - End with RFCPING call (tags 0x0502, 0x000b, 0x0102)
   - Read server response; check tag 0x0420 = 0 for success

---

*Document created: 2026-06-26*
*Source: Live Wireshark capture of SAP A4H (sysnr=00) via pyrfc/STFC_CONNECTION*
*Gate C status: CLOSED — all critical fields identified; OQ-C01 (password scrambling) RESOLVED 2026-06-27 via BN decompilation (Phase 04 Plan 01), live byte-for-byte truth-check pending Task 3*
*See also: [framing.md](framing.md) (Gate A — CLOSED), [serialization.md](serialization.md) (Gate B — SUBSTANTIALLY CLOSED)*
