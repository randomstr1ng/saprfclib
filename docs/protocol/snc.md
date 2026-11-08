# SNC (Secure Network Communications) Layer

**Status:** CONFIRMED — live SNC handshake against CommonCryptoLib X.509 passed 2026-08-05,
re-confirmed against a second lab system on 2026-11-08. The frame codec and GSS binding are
additionally proven offline against a mock GSS library.
**Confidence:** HIGH for every implemented path; see [Known Gaps](#known-gaps).

---

## Overview

SNC wraps SAP's Network Interface (NI) payloads in a GSS-API-protected frame. It sits at the
**transport layer** — below the RFC/CPIC protocol, above raw TCP. An `SncTransport`
wraps any inner `Transport` (see [framing.md](framing.md)) and intercepts `send_message` /
`recv_message`; the `Connection` and all protocol layers above it are transparent to SNC.

```
RfcInvoke() / logon TLV                — RFC application + handshake payloads
  → Connection.send_message(payload)   — plain RFC/CPIC bytes (see framing.md)
    → SncTransport.send_message()       — gss_wrap / gss_get_mic per negotiated QOP
      → build_snc_frame()               — prepend the 0x18-byte SNC header
        → inner Transport.send_message() — NI framing + TCP writev (framing.md)
```

The GSS mechanism underneath is either saprfclib's own implementation of SAP's X.509
mechanism ([snc-mechanism.md](snc-mechanism.md)) or a native GSS-API library loaded with
`ctypes` from `snc_lib`. The frame layer described here is the same for both.

**Activation:** `snc_pse` / `snc_credential` (built-in mechanism) or `snc_lib` (native
library) switch SNC on; `snc_partnername` is then required. Without them the plain TCP
path is byte-for-byte unchanged.

---

## SNC Frame Format

The SNC frame is the only wire structure SNC itself owns — everything inside it is either a
GSS token or protected application data.

### Wire Layout

```
Offset  Length  Type        Name          Notes
 0x00     8      bytes       eye_catcher   b"SNCFRAME" (no trailing NUL in the field)
 0x08     1      uint8       frame_type    2=FR_INIT, 4=FR_ACCEPT, 7=plain, 8=integrity, 9=privacy
 0x09     1      uint8       version       Protocol version = 6
 0x0a     2      uint16-BE   hdr_len       Total header length = 0x18 + extension-header size
 0x0c     4      uint32-BE   token_len     GSS token byte count
 0x10     4      uint32-BE   data_len      Application data byte count
 0x14     2      uint16-BE   mech_id       Mechanism id, 3 for the X.509 mechanism
 0x16     2      uint16-BE   qop_flags     QOP levels on handshake frames, 0 on data frames
[0x18]    var    bytes       ext_headers   Extension headers, ONLY if hdr_len > 0x18
[hdr_len] token_len bytes    gss_token     GSS token bytes
[..]      data_len  bytes    app_data      Application data bytes
```

`struct` format: `>8sBBHIIHH` (24 bytes fixed header). Implemented in
`src/saprfclib/snc.py` as `build_snc_frame` / `parse_snc_frame`.

`hdr_len` includes the 8-byte eye-catcher, so the standard value is `0x18`. When it is
larger, extension headers follow and the GSS token starts at `hdr_len`; `parse_snc_frame`
seeks there, so inbound extension headers are skipped.

### Extension header

Sent on the client's **first** FR_INIT only (later frames have `hdr_len = 0x18`):

```
BE32  slot bitmask        00 00 00 01 = slot 0 present
per set bit:  BE16 length || slot bytes
slot 0 = BE16 mechanism id (00 03)
         || 04 01 || BE16 OID length (00 08) || 06 06 2B 24 03 01 25 01
         || BE32 DN length || DN DER of the partner name
```

Slot 0 is the target name as a GSS exported-name token (RFC 2743 §3.2). The DN is encoded
as the reference client does: RDNs reversed (C first), values as PrintableString, or
T61String when a character falls outside that set, `C` upper-cased, `DC` as IA5String,
`SN` meaning serialNumber. saprfclib refuses non-ASCII partner names: the reference
encodes them as T.61 sequences, and whether a server accepts that is untested.
Source: golden fixture `tests/golden/snc/snc_frame_headers.json` (byte-identical match).

### GW envelope (SNC gateway port)

On the secure gateway port each SNC frame travels inside an 80-byte GW header
(type `06 CB`) followed by an 8-byte trailer `BE32 len(SNC frame) || 00 00 85 00`.
Handshake and data frames differ in two places: byte 10 is `0x28` on handshake frames and
`0x08` on data frames, and bytes 48:52 are `00 00 85 00` on handshake frames and zero on
data frames. Bytes 78:80 carry the connection index the gateway assigned in its CONNECT
reply, which the client echoes in every later frame. Source: same fixture.

### DoS Guard

`parse_snc_frame` validates the declared `token_len + data_len` against a 128 MiB cap
(`_MAX_FRAME_BYTES`) **before** slicing or allocating — mirrors the NI-length check in
[framing.md](framing.md). A declared length is attacker-controlled input: check it before you
allocate against it, not after.

### Frame Detection (passthrough)

Every inbound frame's first bytes are checked against the eye-catcher. A frame that does
**not** begin with it is non-SNC NI traffic and is passed through unchanged — `SncTransport`
must never corrupt a non-SNC frame.

---

## Handshake

The SNC context is established with a standard GSS-API initiator/acceptor loop.

```
Client                                Server
  │  FR_INIT (type 2) + gss_init token  │   gss_init_sec_context() → output token
  │ ───────────────────────────────────▶│   gss_accept_sec_context()
  │  FR_ACCEPT (type 4) + gss_accept tok │
  │ ◀───────────────────────────────────│
  │  (repeat while GSS_S_CONTINUE_NEEDED)│
  │  ...                                 │
  │  handshake COMPLETE                  │   both sides: GSS_S_COMPLETE
```

1. Client calls `gss_init_sec_context` (input token empty on the first call →
   `GSS_C_NO_BUFFER`) and sends the output token in an **FR_INIT** (type 2) frame.
2. Server replies with an **FR_ACCEPT** (type 4) frame carrying its accept token.
3. The loop repeats while `gss_init_sec_context` returns `GSS_S_CONTINUE_NEEDED`.
4. On `GSS_S_COMPLETE`, the context is established and data frames (type 7/8/9) may flow.

**Handshake before data:** no application data is
wrapped or sent until the handshake reaches `GSS_S_COMPLETE`. `SncTransport` sets an
`_established` gate only inside `_handshake` and re-asserts it at the top of
`send_message` (belt-and-suspenders).

### Per-connection lifecycle

Initialisation order, which matters — the credential must exist before the partner name is
imported against it:

```
session init → set own name (snc_myname) → session start
             → import partner name (snc_partnername) → acquire credential
```

`saprfclib` implements the **initiator (client)** role only; the acceptor role is not
implemented. `GssBinding.__init__` acquires an initiator credential (`GSS_C_INITIATE`), then
imports the partner name.

---

## GSS-API Binding

An SNC implementation loads the GSS library at runtime and resolves a small set of standard
RFC 2744 entry points. `saprfclib` does the same with `ctypes.CDLL(snc_lib)` — there is no GSS
reimplementation here, and no cryptography of our own. The crypto is delegated wholesale to
the user-supplied `.so`.

The six required functions:

| Function                  | Used for                                   |
|---------------------------|--------------------------------------------|
| `gss_init_sec_context`    | Client handshake init token (FR_INIT)      |
| `gss_accept_sec_context`  | Acceptor path (server role — deferred)     |
| `gss_wrap`                | QOP 3 privacy — encrypt payload            |
| `gss_unwrap`              | QOP 3 privacy — decrypt payload            |
| `gss_get_mic`             | QOP 2 integrity — produce MIC              |
| `gss_verify_mic`          | QOP 2 integrity — verify MIC               |

Four helpers are also resolved: `gss_import_name`, `gss_acquire_cred`,
`gss_release_buffer`, `gss_release_name`. Every mech-allocated output buffer is copied to
Python `bytes` and freed via `gss_release_buffer` — a mech-allocated buffer that is never
released is a leak in a long-lived pooled connection.

This binding is **provider-agnostic**: CommonCryptoLib (`libsapcrypto.so`, X.509),
`libgssapi_krb5.so` (Kerberos), or any RFC 2744-compliant library works unchanged.
`minikerberos` is deliberately **not** used — it does not implement `gss_wrap` / `gss_unwrap`
for message protection above QOP 1.

`ctypes` struct definitions (`gss_buffer_desc`, `gss_OID_desc`) follow RFC 2744 §3.1–3.2
and were verified against `libgssapi_krb5.so.2`.

---

## QOP Levels

Quality of protection:

| QOP | Name           | Frame type | GSS calls                         |
|-----|----------------|------------|-----------------------------------|
| 1   | authentication | 7 (PLAIN)  | none (no data protection)         |
| 2   | integrity      | 8 (INTEG)  | `gss_get_mic` / `gss_verify_mic`  |
| 3   | privacy        | 9 (PRIV)   | `gss_wrap` / `gss_unwrap`         |

### Negotiation

Handshake frames carry three 2-bit levels in `qop_flags`: bits 1–2 minimum, bits 3–4
maximum, bits 5–6 the level in use. `snc_qop` *q* = 1, 2 or 3 sends min = use = *q*,
max = 3; `snc_qop` 8 and 9 both send 3/3/3. When the server's FR_ACCEPT announces a
minimum above the level in use, the client raises its level to that minimum and sends the
raised triple in its next FR_INIT. Data frames then use the frame type of the final level
and carry 0 in `qop_flags`.

| `snc_qop` | 1st FR_INIT | 2nd FR_INIT (server answered `0x7e`) | data frames |
|---|---|---|---|
| 1 | `0x3a` (1/3/1) | `0x7a` (1/3/3) | type 9 |
| 2 | `0x5c` (2/3/2) | `0x7c` (2/3/3) | type 9 |
| 3, 8, 9 | `0x7e` | `0x7e` | type 9 |

Source: golden fixture `tests/golden/snc/snc_frame_headers.json`, a reference client against
a server configured with `snc/data_protection/min = 3`. Types 7 and 8 on the wire need a
server with a lower minimum and have not been observed live; the frame layouts follow the
table above.

On receive, saprfclib refuses any data frame protected below its own minimum, and any
non-data frame once the channel is established. A frame's type is chosen by the sender,
so this is where a downgrade is stopped.

`saprfclib` defaults to `snc_qop=3` (privacy).

**No cleartext password:** at QOP 3 every payload — including the logon
TLV carrying the scrambled password — passes through `gss_wrap`, so the raw payload bytes
never reach the socket in cleartext. No plain (type 7) frame is emitted at QOP ≥ 3. This is
confirmed offline by an opaque `gss_wrap` mock (the test asserts the plaintext never appears
in the wrapped output) and is re-verified on the wire at the live checkpoint.

---

## Parameter API

`saprfclib.connect()` kwargs mirror SAP's `SNC_*` env var names in snake_case:

| kwarg             | SAP env var        | Meaning                                                    | Default |
|-------------------|--------------------|------------------------------------------------------------|---------|
| `snc_lib`         | `SNC_LIB`          | Path to the GSS provider `.so` (required for SNC)          | —       |
| `snc_partnername` | `SNC_PARTNERNAME`  | Server GSS identity, e.g. `p:CN=SAP Server,...`            | —       |
| `snc_myname`      | `SNC_MYNAME`       | Client identity (optional; lib default if absent)         | `None`  |
| `snc_qop`         | `SNC_QOP`          | QOP level 1 / 2 / 3                                        | `3`     |
| `snc_sso`         | `SNC_SSO`          | Log on with the SNC identity instead of a password (see Known Gaps) | `False` |

**Quote stripping:** `SNC_MYNAME` and `SNC_PARTNERNAME` may arrive wrapped in double quotes
from the SAP environment. `GssBinding` strips a single enclosing quote pair before passing the
value to GSS — matching SAP's own behaviour, which is why a quoted partner name works there
and would otherwise fail here.

**Partner name must be the server's full DN.** The server certificate's subject is compared
with `snc_partnername` RDN by RDN. Observed against a live system (2026-11-08) whose
certificate subject is `C=DE, O=SAP Trust Community, OU=SAP Web AS, OU=IDEMOSYSTEM, CN=A4H`:

| `snc_partnername` | Result |
|---|---|
| `p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE` | accepted |
| same, without spaces after the commas, or with `;` separators | accepted |
| same, attribute names or values in a different letter case | accepted |
| `p:CN=A4H` alone, or with any RDN missing | rejected, GSS minor `0xA2200202` |
| RDNs in a different order (including the two `OU`s swapped) | rejected, `0xA2200202` |
| a value with different inner whitespace (`SAP  Web AS`) | rejected, `0xA2200202` |

The text form lists the most specific RDN first (`CN=` leftmost), the reverse of the
certificate's DER order.

**Credential discipline:** `snc_lib`, `snc_partnername`, and `snc_myname` are
**never** logged, echoed into an exception message, or placed into any `repr`. `SncError`
carries the GSS `major` / `minor` status codes only — never token or name bytes.

---

## Known Gaps

Values that could not be established without a live capture are recorded here rather than
invented. Nothing below is guessed into the implementation.

### SNC eye-catcher (8 bytes) — RESOLVED

The 8-byte eye-catcher at frame offset `0x00` is **`b"SNCFRAME"`** — eight characters, with no
trailing NUL inside the field. `SncTransport` uses this as its default; the `eye_catcher`
parameter remains injectable for testing.

### SNC logon without a password (`snc_sso`) — RESOLVED

`snc_sso=True` logs on with the SNC identity: the server maps the client certificate to a
user (SU01 → SNC). It changes **only the logon records**; the SNC frames, including their
extension header, are identical to a password logon. Compared with a password logon
inside SNC, the logon omits the scrambled password (0x0117) and an empty 0x0675 record,
and omits the user (0x0111) when no user is given. A password passed together with
`snc_sso=True` is not sent, as with the reference client. Source: golden fixture
`tests/golden/snc/snc_logon_tlvs.json`; confirmed live with both mechanisms (logged on as
the mapped user; an unmapped user is refused with "Name or password is incorrect").

This is unrelated to SAP logon tickets (`MYSAPSSO2`), which saprfclib does not support.

### CommonCryptoLib GSS mechanism OID — RESOLVED

CommonCryptoLib (`libsapcrypto.so`) uses a SAP-specific GSS mechanism OID rather than a
standard Kerberos mechanism: `1.3.36.3.1.37.1`, DER-encoded as
`\x06\x06\x2b\x24\x03\x01\x25\x01` (8 bytes). This is `_SAP_SNC_OID` in `snc.py`, and
the context ID `_SNC_CTX_ID = 3` was confirmed from a live capture.

`_build_snc_ext_header()` builds the mechanism extension header from these two values. The full
CommonCryptoLib X.509 handshake was confirmed end-to-end against a live system on 2026-08-05.

---

## Cross-References

- [Framing](framing.md) — the NI/CPIC framing SNC wraps
- [Handshake](handshake.md) — the logon TLV sequence SNC protects at QOP 3
- [Serialization](serialization.md) — ABAP type encoding inside the protected payload
- `src/saprfclib/snc.py` — frame codec, `GssBinding`, `SncTransport`, `connect_snc`

---

*Live SNC handshake confirmed 2026-08-05 against CommonCryptoLib X.509, partner `p:CN=A4H`.*
*Not implemented: the acceptor (server) role.*
