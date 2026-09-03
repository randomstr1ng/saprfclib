# SAP RFC Logon Handshake Protocol

## Status

**CONFIRMED — live capture 2026-06-26 (SAP NetWeaver 7.58, sysnr=00, port=3300).**

The full logon sequence is documented below, frame by frame, and replayed from golden
fixtures in CI.

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

After codepage `4103` is selected, all string data in every subsequent RFC frame is **UTF-16LE**.
This is SAP's wide-character wire encoding: one character is two bytes, and every length in a
character-typed field is a count of characters, not bytes.

**Implementation note:** parse the server's NI_VERSION response and store the negotiated
codepage. If it is `4103`, use `utf-16-le` — explicitly little-endian, never bare `utf-16`,
which would prepend a BOM the wire format does not have. Codepage `1100` (Latin-1) would imply
single-byte encoding, but in practice every system tested enforces Unicode mode.

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
| 0x0117 | 17 | binary | Scrambled password: `seed(4B) + scramble(pw, seed)` — see "Password scrambling" below |
| 0x0115 | 1 | ASCII "E" | Logon language |
| 0x0501 | 1 | 0x01 | `0x01` in every LOGON captured, and present in no other frame type. Meaning unknown; constant so far. |
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

**Note on RFCPING:** the logon TLV ends with a call to `RFCPING`. This is not an application
function call — it is the protocol-level logon probe. The server processes the credentials and
returns the logon response (frame 15). `RFCPING` means "validate this connection".

**Note on the logon language (tags 0x0011 / 0x0115):** the wire carries the **one-character
SAP language code** as a single ASCII byte — `"E"` on both tags in this capture. That single
character is the whole of what the protocol transports; there is no two-character form on the
wire.

`saprfclib.connect(lang=…)` accepts either the one-character SAP code or the two-character ISO
code, matching the SDK's `LANG` connection option. A one-character code is passed through
untouched; a two-character code is converted to its SAP code first. Both end up as one byte in
the frame.

The SDK behaves the same way. Its `LANG` handling converts any input longer than one character
through the SAP kernel's language routine before the logon frame is built, and refuses the
connection with `RFC_INVALID_PARAMETER` when the code will not map. `pyrfc` adds nothing here —
it hands `LANG` straight to `RfcOpenConnection` and lets the SDK convert, while re-exporting the
SDK's two public conversion calls as `language_iso_to_sap` / `language_sap_to_iso`.

The mapping is not derivable by rule. `EN`→`E` and `DE`→`D` look like a first-letter rule, but
`ES`→`S`, `DA`→`K`, `FI`→`U`, `EL`→`G` and `ZH`→`1` are not. saprfclib carries the table in
`saprfclib.language` and exposes the same two helper names pyrfc uses. See that module's header
for how the mapping was established and why an unknown code raises there but not in the SDK.

**Note on parsing the RFCPING response:** it is an ordinary RFC response and uses the full wire
dialect — a GW frame, records that may use the extended-length form, and a repeated close tag
after each record. A reader that skips the close-tag suffix desynchronises by two bytes after
the first record and misreads every tag and length thereafter, which surfaces as a spurious
"length exceeds remaining payload". A response that happens to place the return code `0x0420`
first will hide the bug, because the walk returns before it can drift.

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

**`0x0450` is not guaranteed.** The table above is a kernel 793 capture. A 7.52 system
answers with none of `0x0450`/`0x0451`/`0x0452`/`0x0453` — it identifies itself through
`0x0008` (`host_SID_instance`), `0x0006`, `0x0007` and `0x0018` instead. See
`tests/golden/framing/signon_incomplete_752_response.bin`.

Consequence for callers: `ConnectionAttributes.sys_id` can legitimately be empty. Nothing
may key on it unconditionally — the in-process descriptor cache in particular, since two
connections to two different unidentified systems would otherwise share one bucket and a
`FunctionDesc` carries no record of the system it came from. `Connection` substitutes a
token unique to the connection in that case (`Connection._metadata_cache_key`): repeat
calls on one connection still skip the round-trip, and nothing is shared between systems
that never identified themselves.

Deriving a SID from `0x0008` by splitting on `_` is **not** done: the three-part shape of
`vhcala4hci_A4H_00` is a naming convention, not a protocol guarantee, and inventing a
system identity from it would be an unsourced inference of exactly the kind this project
does not ship.
| 0xFFFF | 0 | — | TLV stream terminator |

### Fixture

The logon request and response fixtures (frames 14 and 15) are stored in `tests/golden/framing/`:
- `tests/golden/framing/logon_request.bin` + `.json`

The response (frame 15) is not yet extracted as a standalone fixture — add as needed.

---

## WebSocket RFC — the LOGON frame

**Status: the shape below is what a working client sends. saprfclib does not yet
send it, which is issue #14.**

A reference SDK client (NW RFC 7.50 PL18) opening a wRFC session against A4H
kernel 793 sends a **238-byte** LOGON frame containing nineteen records:

```
0101  8   0301010101010000        capability bits
0103  4   00000e0b
0106  11  04010003000a0200000023
0514  16  session token
0114  3   "001"                   client
0111  9   "Developer"             user
0117  17  password material
0115  1   "E"                     language
0501  1   01
0007  9   "127.0.1.1"             client IP
0011  1   "E"
0012  3   "754"                   own release
0013  3   "754"
0008  5   "titan"                 client hostname
0006  9   "<unknown>"
0130  8   "startrfc"              CLIENT PROGRAM NAME
0502  0                           request marker
000b  3   "754"
0102  7   "RFCPING"               FUNCTION NAME
ffff  0                           terminator
```

### Three things the earlier LOGON builder had wrong

All three are fixed (issue #14). The frame above is what the library now sends.

**There is no `0x5001` ngrfc record.** The function to run is named in `0x0102`
and the record set ends. The earlier builder wrapped a `0x5001` record around an
ngrfc body; the server then tried to receive RFC data from it and answered
`CALL_FUNCTION_RECEIVE_ERROR` — which describes exactly that. Two values were
tried in that record, an empty body and `b"\x45"`, and both failed because the
record should not have been there at all.

**The request is single-byte; the response is UTF-16LE.** The wire is asymmetric.
`"001"` occupies 3 bytes going out and `"A4H"` occupies 6 coming back. The reply
carries `0x0016 = "1100"`, a single-byte codepage, while the session's negotiated
partner codepage is `4103` — so the LOGON is exchanged in 1100 and the session
moves to 4103 after it. The earlier builder encoded the LOGON as UTF-16LE
throughout, which made its frame roughly twice the size for the same strings.

**`0x0130` is the client program name**, `"startrfc"` — 8 bytes, unpadded. The
earlier builder put an 80-byte padded function name there.

### The LOGON runs the function it names

Its reply is a full RFC result, not a bare acknowledgement, and has to be read as
one. The authentication tags are filled in whether or not the embedded call
succeeded, so a reply carrying an exception still looks like a clean logon to
anything that only checks for a `sys_id` — which is how the earlier failure went
unnoticed. `_ws_logon_failure` reads the result before the session is declared
usable.

### What is still not established

Whether this is the only valid shape. It is what a reference client sends and
what A4H accepts; a server wanting something different would not appear in either
observation. This is the `[ASSUMED]` label on `_build_ws_logon_message`.

Whether `0x0514` is required on frames after the LOGON. Omitting it from the
LOGON is accepted, and its value in a reference trace has a stable 9-byte prefix,
so it is host-derived rather than random — a random one drew silence. The second
`[ASSUMED]` label covers this.

*Source: a reference-client trace against the authors' own system, decoded in
`parse_sdk_trace.py`, then confirmed by capturing this library sending the same
shape and the server accepting it — `tests/golden/framing/wrfc_logon_accepted.bin`.
The password field is documented under "Password scrambling" below; on wRFC the
scrambled body is single-byte, matching the rest of the request.*


## Password scrambling (0x0117)

!!! danger "This is obfuscation, not encryption"
    The 17-byte `0x0117` record is **not a cryptographic hash and not encryption**. It is a
    reversible byte cipher with a client-chosen seed transmitted in the clear alongside the
    ciphertext. Anyone who can read the frame can recover the password. Passwords on a plain
    RFC connection are effectively in the clear on the network — use SNC or WebSocket RFC over
    TLS for any connection leaving a trusted segment.

The record is a 4-byte client-generated random seed followed by the scrambled password bytes:

```
0x0117 value (17 bytes for the captured 13-character password):

  [ seed: 4 bytes LE ]  [ scramble(password_bytes, seed) : N bytes ]
                          N = len(password) in the password codepage
  total = 4 + N

scramble(buf, len, seed):                 # symmetric XOR stream; its own inverse
    k  = (((seed >> 5) ^ (seed * 2)) ^ seed) & 0x3f
    ck = 0xffffffff
    for i in range(len):
        ks   = (ck * i) & 0xffffffff
        kb   = (ks ^ kt[k]) & 0xff
        buf[i] ^= kb
        k  = (k + 1) & 0x3f
        ck = (ck + seed) & 0xffffffff

kt (64-byte key table):
    f0ed53b83244f1f876c67959fd4f13a2
    c15195ec5483c234774943a27de26596
    5e5398789a17a33cd383a8b829fbdca5
    55d7027784 13acddf9b8311 6610e6dfa   (whitespace cosmetic)
```

Implemented as `_scramble_password` in `src/saprfclib/connection.py`, verified against a live
logon reaching READY (`0x0420 == 0`).

**Seed:** the seed is stored **little-endian** (x86 native), unlike the big-endian NI and TLV
headers. It is freshly generated per scramble on the client — there is **no server-supplied
nonce**, and neither the `0x0514` session token nor the codepage tags feed into it. A replayed
frame therefore replays successfully; the seed provides no anti-replay property.

**Password codepage:** a 13-character ASCII password produces exactly 13 scrambled bytes,
which means the password is scrambled as **single-byte** characters even though the session
negotiated `4103` (UTF-16LE) for every other string. `saprfclib` uses single-byte, confirmed
by a live logon. Behaviour for non-ASCII passwords is untested — treat it as an open question.

---

## Key Protocol Facts

| Finding | Evidence | Confidence |
|---------|----------|------------|
| Codepage negotiated in NI_VERSION at offset 24 | Frame 4 proposes "1100", frame 6 selects "4103" | HIGH — live capture |
| Codepage 4103 = UTF-16LE (Unicode mode) | Confirmed in frames 6 and 13 | HIGH — live capture |
| COM_HEAD only in the logon frame | Frame 14 has it; frames 19/21/24/35 do not | HIGH — live capture |
| Connection handle = 8-byte ASCII decimal | Frame 9 assigns "75568442", reused in all later frames | HIGH — live capture |
| Logon TLV uses 0x0114 / 0x0111 / 0x0117 for client / user / password | Frame 14 TLV parse | HIGH — live capture |
| Password field is tag 0x0117, 17 bytes for a 13-character password | Frame 14 TLV parse | HIGH — live capture |
| 0x0117 = `seed(4B) + scramble(pw, seed)` — a reversible cipher, not a hash | Derived, then confirmed by a live logon reaching READY | HIGH |
| Server response carries SID (0x0450), release (0x0012), user (0x0150) — on kernel 793 | Frame 15 TLV parse | HIGH — live capture |
| A 7.52 server sends no 0x0450/0x0452/0x0453 at all; sys_id is legitimately empty | `signon_incomplete_752_response.bin` | HIGH — live capture |
| Logon always calls RFCPING as its probe (tag 0x0102 in the logon TLV) | Frame 14 | HIGH — live capture |

---

## Open Questions

| # | Question | Urgency | Notes |
|---|----------|---------|-------|
| OQ-C02 | Tag 0x0106 (11 bytes): codepage negotiation detail | MEDIUM | Present in both request and response; binary content not decoded |
| OQ-C03 | Tag 0x0101 (8 bytes): capability flag bit layout | MEDIUM | Differs between client request and server response |
| OQ-C04 | GW_INFO (type 0x060F) body layout | LOW | Frame 10 carries network routing info; not required for logon |
| OQ-C05 | Non-ASCII password codepage | LOW | Single-byte scrambling confirmed for ASCII only |

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

*Source: live capture of an `STFC_CONNECTION` session, SAP NetWeaver 7.58, sysnr=00, port 3300.*
*See also: [Framing](framing.md), [Serialization](serialization.md).*
