# Built-in SNC Mechanism (X.509, OID 1.3.36.3.1.37.1)

**Status:** CONFIRMED for the client role — a live handshake, logon and RFC calls against
an SAP S/4HANA lab system on 2026-11-08, plus a full record-layer exchange with SAP
CommonCryptoLib acting as the acceptor.
**Implemented in:** `src/saprfclib/secgss.py` (mechanism), `src/saprfclib/pse.py`
(credentials).
**Evidence:** golden fixtures `tests/golden/snc/secgss_live_handshake.json` (live server)
and `tests/golden/snc/secgss_loopback_records.json` (CommonCryptoLib acceptor), replayed
byte for byte by `tests/test_secgss.py`.

This page describes the GSS tokens that travel inside the SNC frames of
[snc.md](snc.md). The frame layer is unchanged: the built-in mechanism produces the same
tokens a native GSS library would, and `SncTransport` carries them the same way.

---

## Scope

Only what was observed end to end is implemented:

| Parameter | Value |
|---|---|
| Protocol version | 1.1 |
| Cipher suite | `0x0009` — ephemeral ECDH on P-256, AES-256-CBC, HMAC-SHA256, P_SHA256 PRF |
| Authentication | X.509 certificates on both sides, RSA PKCS#1 v1.5 signatures (SHA-512 or SHA-256) |
| Role | initiator (client) only |

Anything else the server selects is refused with `SncError`. Kerberos, RSA key
transport, other curves and the older token formats are not implemented.

---

## Tokens

Every token is a DER `SEQUENCE` that starts with the mechanism OID:

```
30 82 LL LL  06 06 2B 24 03 01 25 01  <body>
```

Handshake tokens carry a body of `A0 82 LL LL` followed by one or more handshake
messages, each a complete DER element. The reference implementation writes both the
outer length and the container length in the two-byte long form (`82 LL LL`) regardless
of size; the built-in mechanism does the same.

| Tag | Message |
|---|---|
| `A1` | ClientHello |
| `A2` | ServerHello |
| `A3` | KeyExchangeKey |
| `A4` | AuthRequest |
| `A5` | AuthResponse |
| `A6` | KeyTransport |
| `87` | Finished (primitive: an OCTET STRING holding one data token) |
| `AA` | Alert — the peer aborts the handshake |

### Message flow

```
Client                                          Server
 token 1  ClientHello                       ──►
 token 2                                    ◄──  ServerHello, KeyExchangeKey, AuthRequest
 token 3  KeyTransport, AuthRequest,
          AuthResponse, Finished            ──►
 token 4                                    ◄──  AuthResponse, Finished
```

`gss_init_sec_context` semantics: CONTINUE_NEEDED after tokens 1 and 3, then COMPLETE
with no output token once token 4 has been verified.

A first token holding only a ClientHello is accepted by the live system. (The reference
client wraps its first token in an older compatibility envelope and adds messages the
server ignores; neither is needed.)

### ClientHello

```
A1 { OCTET STRING params, OCTET STRING random(32), [1] { extension, ... } }
```

- `random` = 4-byte big-endian seconds since the epoch, then 28 random bytes. The
  ServerHello random has the same layout.
- `params` = seven counted lists:
  `02 01 01` (versions: 1.1), then one-entry lists for MAC `01` (HMAC-SHA256),
  cipher `01` (AES-256), handshake hash `02` (SHA-256), PRF `02` (P_SHA256),
  data encoding `02` (header v1) and key exchange `04` (server ECDHE).
- Extensions, each `SEQUENCE { INTEGER id, value }`:
  `3` = OCTET STRING of 16-bit big-endian cipher-suite ids (`00 09`);
  `5` = NULL (sent by the reference client; kept).

### ServerHello

```
A2 { OCTET STRING params(8), OCTET STRING random(32) }
params = 01 01 | suite (BE16) | chunk size (BE32)
```

The live system answered `01 01 0009 00004000`: version 1.1, suite `0x0009`, chunk size
16384. The chunk size governs the record layer in both directions.

### Key exchange

- Server `KeyExchangeKey`: `A3 { A2 <SubjectPublicKeyInfo contents> }` — an implicitly
  tagged X.509 SPKI with an `id-ecPublicKey` P-256 key.
- Client `KeyTransport`: `A6 { 83 41 <uncompressed point 04 || X || Y> }`.
- **Pre-master secret = the X coordinate of the shared point, big-endian, always 32
  bytes** (leading zero bytes kept).

### Authentication

- `AuthRequest` = `A4 { A1 { [0] mode?, OCTET STRING sigalgs, ... } }`. `sigalgs` is a
  3-byte big-endian byte count followed by 32-bit algorithm ids. The client sends only
  the list; the server also sends the mode (1 = requested), the subjects of the CAs it
  trusts, and further fields the client does not need.
- `AuthResponse` = `A5 { A1 { Signature, SEQUENCE OF Certificate } }`, `Signature` being
  `SEQUENCE { AlgorithmIdentifier, BIT STRING }`.
- Each side signs **the concatenation of every handshake message so far, exactly as
  sent** (each message's complete DER element, both directions, container and outer
  header excluded). The client's signature covers everything up to and including its own
  AuthRequest; the server's covers everything up to and including the client's Finished.
- The signer picks the first id in the *peer's* list that it supports. The built-in
  client offers `01000601` (RSA PKCS#1 v1.5 SHA-512) then `01000201` (SHA-256); the live
  server chose SHA-512, and so does the client when the server lists it first.

### Key schedule

TLS 1.2 `P_SHA256` (RFC 5246 §5), label and seeds concatenated in the order shown:

```
master    = P_SHA256(pms,    "master secret"              || client_random || server_random)[:48]
client_kb = P_SHA256(master, "client write key expansion" || server_random || client_random)[:80]
server_kb = P_SHA256(master, "server write key expansion" || server_random || client_random)[:80]
kb        = mac_key[32] || enc_key[32] || iv[16]
```

Each direction has its own PRF invocation (unlike TLS's single key block). The client
sends with the client block and receives with the server block. The `iv` part is not used
by the record layer.

### Finished

```
verify_data = P_SHA256(master, "client finished" | "server finished" || SHA-256(transcript))[:12]
```

`transcript` is the same message concatenation the signatures use, taken just before the
Finished message. `verify_data` is sent as a **data token with sequence number 0** (see
below) inside the `87` element. Application data therefore starts at sequence number 1 in
each direction.

---

## Data tokens

```
30 84 <BE32 length>  06 06 2B 24 03 01 25 01
04 0A <BE64 sequence number> <flags: 01 01 wrap / 00 00 MIC>
04 84 <BE32 body length> <body>
```

The header is always 32 bytes. The message is split into chunks of the negotiated chunk
size (one empty chunk for an empty message); chunk *i* is protected as:

```
padlen = 16 - ((len(chunk) + 32) mod 16)          # 1..16, never 0
pad    = padlen copies of the byte padlen          # value = padlen, NOT padlen - 1 as in TLS
hdr18  = BE64 seq || BE32(len(chunk) + padlen) || BE32 i || 01 01
mac    = HMAC-SHA256 over hdr18 || chunk || pad    # see "running MAC" below
body  += IV(16 random bytes) || AES-256-CBC(enc_key, IV, chunk || pad || mac)
```

MIC tokens carry one 32-byte MAC per chunk over `hdr18 || chunk`, where `hdr18` uses the
plain chunk length; the data itself is not in the token.

**Running MAC.** Each direction keeps *one* HMAC-SHA256 state for the whole session, keyed
once with `mac_key`. Every MAC input — Finished, wrap and MIC records alike — is appended
to it, and each record carries the digest of everything fed so far. The state is never
reset. Every record of both directions in both fixtures, server records included,
verifies only under this rule.

**Sequence numbers.** One per token, shared by all its chunks, incremented after each
token. The receiver accepts exactly the next number: a lower one is a replay
(GSS_S_DUPLICATE_TOKEN), a higher one a gap (GSS_S_GAP_TOKEN). A rejected token leaves the
running MAC in an undefined state, so the connection must be dropped.

**Empty messages.** The reference implementation refuses to wrap an empty message; the
built-in mechanism raises `ValueError` rather than produce one.

---

## Server certificate checks (client side)

All of these fail closed with `SncError`:

1. The server's signature must verify over the transcript with the certificate's key.
2. The certificate must be one of the trusted certificates, or chain to one through RSA
   PKCS#1 v1.5 signatures (SHA-256/384/512) over certificates the server sent.
3. Every certificate on that path must be within its validity period; if the leaf has a
   key-usage extension it must allow digital signatures.
4. The leaf subject must match `snc_partnername` under the rules in
   [snc.md](snc.md#parameter-api).
5. The server's Finished value must match.

Revocation is not checked.

---

## Credentials (`pse.py`)

A PSE file created with `sapgenpse` holds the own key, own certificate, its issuer chain
and the trusted certificates (the "PK list"). Supported: container versions 2 and 4,
protected with PKCS#12 `pbeWithSHAAnd3-KeyTripleDES-CBC` (the default) or PBES2 / PBKDF2
(HMAC-SHA1/256/512) / AES-256-CBC, or unprotected; RSA keys only. Golden files:
`tests/golden/pse/*.pse`, each paired with the key and certificates `sapgenpse` exported
from it.

Not supported: PSEs inside local protected storage (LPS), reading the PIN from a
`cred_v2` file (`sapgenpse seclogin`), EC and EdDSA own keys.

---

## Security notes

- **Not constant-time.** The AES, RSA and ECDH implementations are pure Python. Their
  timing depends on secret data, so a local attacker able to time many operations could
  in principle learn key material. `tlslite-ng` applies RSA blinding to private-key
  operations. Use the built-in mechanism on hosts you control.
- **Performance.** Pure-Python AES runs at roughly a few MB/s; reading a 40 000-row table
  over SNC took 2.4 s in the live test. `tlslite-ng` switches to a native backend
  automatically if one is installed.
- **Trust anchors are explicit.** Only certificates in the PSE's PK list (or the
  credential's `trusted` tuple) are trusted; there is no system trust store fallback.

---

## Open questions

- Which suites besides `0x0009` a server will accept from a client that offers them
  (P-384/P-521 variants, RSA key transport) — not exercised.
- ECDSA own keys and ECDSA server certificates — not exercised.
- Context expiry or re-keying on long-lived sessions — not observed.
