# SNC (Secure Network Communications) Layer

**Status:** CONFIRMED — BN decompilation of the frame codec + GSS binding CONFIRMED; live
SNC handshake gate PASSED 2026-08-05 (CommonCryptoLib X.509, partner p:CN=A4H).
**Gate status:** PASSED — offline codec/handshake proven via `MockGssLib` + live SNC
handshake passed (SEC-02/03/06, 2026-08-05). D-22 (eye-catcher) and D-24 (OID) resolved;
D-23 (extension headers) partial — basic SNC with fixed 0x18 header works, SSO2 deferred.
**Confidence:** HIGH for all implemented paths (Binary Ninja HLIL of `SncPMakeFrame` /
`SncPUnFrame` / `SncPFrameIn` / `SncDetectFrame` / `STISncInit` in `libsapnwrfc.so`);
D-23 SSO2 extension headers remain unimplemented (`NotImplementedError`).

---

## Overview

SNC wraps SAP's Network Interface (NI) payloads in a GSS-API-protected frame. It sits at the
**transport layer** — below the RFC/CPIC protocol, above raw TCP (D-01). An `SncTransport`
wraps any inner `Transport` (see [framing.md](framing.md)) and intercepts `send_message` /
`recv_message`; the `Connection` and all protocol layers above it are transparent to SNC.

```
RfcInvoke() / logon TLV                — RFC application + handshake payloads
  → Connection.send_message(payload)   — plain RFC/CPIC bytes (see framing.md)
    → SncTransport.send_message()       — gss_wrap / gss_get_mic per negotiated QOP
      → build_snc_frame()               — prepend the 0x18-byte SNC header (D-02)
        → inner Transport.send_message() — NI framing + TCP writev (framing.md)
```

SNC is **runtime-optional and dependency-free** (D-26): `ctypes` is stdlib, and the GSS
provider `.so` is supplied by the user at connect time via `snc_lib`. There is no build-time
or install-time SNC dependency; `pip install saprfclib` works on any machine, and SNC activates
only when `snc_lib` is passed to `connect()`.

**Activation (D-13):** `snc_lib` presence is the switch — there is no separate mode flag.
`connect(..., snc_lib="/path/to/lib.so", snc_partnername="p:CN=...")` opens an SNC channel;
omitting `snc_lib` leaves the plain TCP path byte-for-byte unchanged (SEC-01).

---

## SNC Frame Format

The SNC frame is the only wire structure SNC itself owns. Confirmed from `SncPMakeFrame`
(builder) and `SncPUnFrame` (parser) via Binary Ninja HLIL of `libsapnwrfc.so`.

### Wire Layout

```
Offset  Length  Type        Name          Notes
 0x00     8      bytes       eye_catcher   b"SNCFRAME" — D-22 RESOLVED (BN RE 2026-07-21: snc_eyecatcher at 0xd88568 → 0xa4b297)
 0x08     1      uint8       frame_type    1=FR_INIT, 2=FR_ACCEPT, 7=plain, 8=integrity, 9=privacy
 0x09     1      uint8       version       Protocol version = 6
 0x0a     2      uint16-BE   hdr_len       Total header length = 0x18 + extension-header size
 0x0c     4      uint32-BE   token_len     GSS token byte count
 0x10     4      uint32-BE   data_len      Application data byte count
 0x14     2      uint16-BE   ctx_id        Context / adapter ID (from snc_handle+0x24)
 0x16     2      uint16-BE   qop_flags     QOP flags (see QOP Levels)
[0x18]    var    bytes       ext_headers   Extension headers, ONLY if hdr_len > 0x18 (D-23 GAP)
[hdr_len] token_len bytes    gss_token     GSS token bytes
[..]      data_len  bytes    app_data      Application data bytes
```

`struct` format: `>8sBBHIIHH` (24 bytes fixed header). Implemented in
`src/saprfclib/snc.py` as `build_snc_frame` / `parse_snc_frame`.

Only the fixed **0x18-byte** header is implemented. A frame with `hdr_len != 0x18`
(extension headers) is rejected with `NotImplementedError` (D-23 — see Documented Gaps).

### DoS Guard

`parse_snc_frame` validates the declared `token_len + data_len` against a 128 MiB cap
(`_MAX_FRAME_BYTES`) **before** slicing or allocating — mirrors the NI-length check in
[framing.md](framing.md) (threat T-07-FRAME-DOS / T-03-DOS parity).

### Frame Detection (passthrough)

`SncDetectFrame` checks the first bytes of every inbound frame against the eye-catcher.
A frame that does **not** begin with the eye-catcher is non-SNC NI traffic and is passed
through unchanged (D-05) — `SncTransport` must never corrupt non-SNC frames.

---

## Handshake

The SNC context is established with a standard GSS-API initiator/acceptor loop, confirmed
from `SncPFrameIn` (the frame-input state machine).

```
Client                                Server
  │  FR_INIT (type 1) + gss_init token  │   gss_init_sec_context() → output token
  │ ───────────────────────────────────▶│   gss_accept_sec_context()
  │  FR_ACCEPT (type 2) + gss_accept tok │
  │ ◀───────────────────────────────────│
  │  (repeat while GSS_S_CONTINUE_NEEDED)│
  │  ...                                 │
  │  handshake COMPLETE                  │   both sides: GSS_S_COMPLETE
```

1. Client calls `gss_init_sec_context` (input token empty on the first call →
   `GSS_C_NO_BUFFER`) and sends the output token in an **FR_INIT** (type 1) frame.
2. Server replies with an **FR_ACCEPT** (type 2) frame carrying its accept token.
3. The loop repeats while `gss_init_sec_context` returns `GSS_S_CONTINUE_NEEDED`.
4. On `GSS_S_COMPLETE`, the context is established and data frames (type 7/8/9) may flow.

**SEC-06 (handshake-before-data, T-07-GSS-BEFORE-COMPLETE):** no application data is
wrapped or sent until the handshake reaches `GSS_S_COMPLETE`. `SncTransport` sets an
`_established` gate only inside `_handshake` and re-asserts it at the top of
`send_message` (belt-and-suspenders).

### Per-connection lifecycle (D-10)

Confirmed from `STISncInit`:

```
SncSessionInit → SncPSetNewName(snc_myname) → SncPSessionStart
              → SncPGSSImportName(snc_partnername) → SncPAcquireCred
```

For the initiator (client) role: `SncSessionInitiatorU`. Phase 7 scope is **client-only**;
the acceptor role (`SncSessionAcceptor`) is deferred. `GssBinding.__init__` reproduces this
order: acquire an initiator credential (`GSS_C_INITIATE`), then import the partner name.

---

## GSS-API Binding (D-06)

SAP loads the SNC library via `dlopen(SNC_LIB)` and resolves exactly **six** function
pointers. `saprfclib` follows the identical pattern with `ctypes.CDLL(snc_lib)` and resolves
the same names — no GSS reimplementation. The crypto is delegated wholesale to the
user-supplied `.so`.

The six required functions (confirmed in `SncIResolveFunctions`):

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
Python `bytes` and freed via `gss_release_buffer` (threat T-07-BUFFER-LEAK).

This binding is **provider-agnostic** (D-07): CommonCryptoLib (`libsapcrypto.so`, X.509),
`libgssapi_krb5.so` (Kerberos), or any RFC 2744-compliant library works unchanged.
`minikerberos` is deliberately **not** used — it does not implement `gss_wrap` / `gss_unwrap`
for message protection above QOP 1.

`ctypes` struct definitions (`gss_buffer_desc`, `gss_OID_desc`) follow RFC 2744 §3.1–3.2
and were verified against `libgssapi_krb5.so.2`.

---

## QOP Levels (D-08)

Quality-of-protection, confirmed from `SncCheck` / `SncInit`:

| QOP | Name           | Frame type | GSS calls                         |
|-----|----------------|------------|-----------------------------------|
| 1   | authentication | 7 (PLAIN)  | none (no data protection)         |
| 2   | integrity      | 8 (INTEG)  | `gss_get_mic` / `gss_verify_mic`  |
| 3   | privacy        | 9 (PRIV)   | `gss_wrap` / `gss_unwrap`         |

SAP's default is `min=1, max=3, use=3`. `saprfclib`'s default is `snc_qop=3` (privacy).

**SEC-04 (no cleartext password, T-07-SEC04):** at QOP 3 every payload — including the logon
TLV carrying the scrambled password — passes through `gss_wrap`, so the raw payload bytes
never reach the socket in cleartext. No plain (type 7) frame is emitted at QOP ≥ 3. This is
confirmed offline by an opaque `gss_wrap` mock (the test asserts the plaintext never appears
in the wrapped output) and is re-verified on the wire at the live checkpoint.

---

## Parameter API (D-12)

`saprfclib.connect()` kwargs mirror SAP's `SNC_*` env var names in snake_case:

| kwarg             | SAP env var        | Meaning                                                    | Default |
|-------------------|--------------------|------------------------------------------------------------|---------|
| `snc_lib`         | `SNC_LIB`          | Path to the GSS provider `.so` (required for SNC)          | —       |
| `snc_partnername` | `SNC_PARTNERNAME`  | Server GSS identity, e.g. `p:CN=SAP Server,...`            | —       |
| `snc_myname`      | `SNC_MYNAME`       | Client identity (optional; lib default if absent)         | `None`  |
| `snc_qop`         | `SNC_QOP`          | QOP level 1 / 2 / 3                                        | `3`     |
| `snc_sso`         | `SNC_SSO`          | SSO2 token mode (D-23 gap → `NotImplementedError`)        | `False` |

**Quote stripping (D-14):** `SNC_MYNAME` and `SNC_PARTNERNAME` may arrive with enclosing
double-quotes from the SAP environment (BN log string `"strip off quotes SNC_PARTNERNAME"`).
`GssBinding` strips a single enclosing quote pair before passing the value to GSS.

**Credential discipline (T-07-CRED):** `snc_lib`, `snc_partnername`, and `snc_myname` are
**never** logged, echoed into an exception message, or placed into any `repr`. `SncError`
carries the GSS `major` / `minor` status codes only — never token or name bytes.

---

## Documented Gaps (live-capture required)

Per the project's no-guessing policy, the following values **cannot** be determined from the
static binary and are recorded honestly rather than invented. Each is resolved by a live SNC
capture at the Phase 7 P03 checkpoint.

### D-22 — SNC eye-catcher (8 bytes)  [RESOLVED]

The 8-byte eye-catcher at frame offset `0x00` was resolved via Binary Ninja RE on 2026-07-21.
The `snc_eyecatcher` global at `libsapnwrfc.so:0xd88568` points to the string `"SNCFRAME\0"`
at `0xa4b297` — the 8-byte wire value is **`b"SNCFRAME"`** (no null terminator in the field).

**Resolution:** `SncTransport` sets `self._eye = b"SNCFRAME"` as the default; the injectable
`eye_catcher` parameter remains available. Source: BN RE 2026-07-21 — `snc_eyecatcher`
global + `SncPMakeFrame` / `SncDetectFrame` (BN HLIL of `libsapnwrfc.so`).

### D-23 — Extension-header format (`hdr_len > 0x18`)  [PARTIAL]

When `hdr_len` exceeds `0x18`, the frame carries extension headers (used for SNC SSO2 tokens
and extended context data). This format has **not** been reverse-engineered. `saprfclib`
implements the fixed 0x18-byte header only:

- `parse_snc_frame` raises `NotImplementedError` on any inbound frame with `hdr_len != 0x18`.
- `snc_sso=True` raises `NotImplementedError` at `SncTransport.__init__`.

Both gates lift only after a live capture confirms the extension-header layout. **No
extension-header byte values are invented.** Source: `SncPMakeFrame` / `SncPUnFrame` (BN RE).

### D-24 — CommonCryptoLib GSS mechanism OID + credential acquisition  [RESOLVED]

SAP uses a **SAP-specific GSS mechanism OID** for CommonCryptoLib (`libsapcrypto.so`):
`1.3.36.3.1.37.1` — DER-encoded as `\x06\x06\x2b\x24\x03\x01\x25\x01` (8 bytes).
Confirmed from BN RE and live SNC handshake gate (2026-08-05). This is `_SAP_SNC_OID`
in `snc.py`. The context-ID `_SNC_CTX_ID = 3` was confirmed from a live `pyrfc` capture.

**Resolution:** `_build_snc_ext_header()` in `snc.py` builds the mechanism extension header
with this OID and `ctx_id=3`. The live SNC gate (SEC-02/03/06, PASSED 2026-08-05) confirmed
the full CommonCryptoLib X.509 handshake. Source: BN RE `SncCheck` + live gate 2026-08-05.

---

## Cross-References

- [framing.md](framing.md) — NI/CPIC framing that SNC wraps (the inner transport)
- [handshake.md](handshake.md) — logon TLV sequence (the payload SNC protects at QOP 3)
- [serialization.md](serialization.md) — ABAP type encoding inside the protected payload
- `src/saprfclib/snc.py` — frame codec, `GssBinding`, `SncTransport`, `connect_snc`
- `.planning/phases/07-security-snc-websocket-rfc/07-CONTEXT.md` — decisions D-01..D-27
- BN RE source: `libsapnwrfc.so` in `sap_rfc_sdk-project.bnpr` — functions `SncPMakeFrame`,
  `SncPUnFrame`, `SncPFrameIn`, `SncDetectFrame`, `SncIResolveFunctions`, `SncInit`,
  `SncCheck`, `STISncInit`, `SncSessionInitiatorU`

---

*Gate status: PASSED — live SNC gate (SEC-02/03/06) passed 2026-08-05; CommonCryptoLib X.509
handshake confirmed with partner p:CN=A4H.*
*Resolved: D-22 (eye-catcher = `b"SNCFRAME"`), D-24 (OID `1.3.36.3.1.37.1`, ctx\_id=3).*
*Partial: D-23 (extension headers — basic SNC with fixed 0x18-byte header works; SSO2 deferred).*
