# Built-in SNC Mechanism (OID 1.3.36.3.1.37.1: X.509 and Kerberos)

**Status:** CONFIRMED for the client role.
- X.509: a live handshake, logon and RFC calls against an SAP S/4HANA lab system on
  2026-11-08, plus a full record-layer exchange with SAP CommonCryptoLib acting as the
  acceptor.
- Kerberos: a live handshake, SNC SSO logon and RFC calls against the same system with
  Active Directory tickets on 2026-11-10, plus a full exchange with CommonCryptoLib as
  the acceptor (see [Kerberos key exchange](#kerberos-key-exchange)).

**Implemented in:** `src/saprfclib/secgss.py` (mechanism), `src/saprfclib/pse.py`
(X.509 credentials), `src/saprfclib/krb5/` (Kerberos tickets, see
[kerberos.md](kerberos.md)).
**Evidence:** golden fixtures `tests/golden/snc/secgss_live_handshake.json` (live server),
`tests/golden/snc/secgss_loopback_records.json` and
`tests/golden/snc/secgss_kerberos_loopback.json` (CommonCryptoLib acceptor), replayed
byte for byte by `tests/test_secgss.py` and `tests/test_secgss_kerberos.py`.

This page describes the GSS tokens that travel inside the SNC frames of
[snc.md](snc.md). The frame layer is unchanged: the built-in mechanism produces the same
tokens a native GSS library would, and `SncTransport` carries them the same way.

---

## Scope

Only what was observed end to end is implemented:

| Parameter | X.509 | Kerberos |
|---|---|---|
| Protocol version | 1.1 | 1.1 |
| Cipher suite | `0x0009` — ephemeral ECDH on P-256, AES-256-CBC, HMAC-SHA256, P_SHA256 PRF | `0x0007` — Kerberos key exchange, AES-256-CBC, HMAC-SHA256, P_SHA256 PRF |
| Authentication | X.509 certificates on both sides, RSA PKCS#1 v1.5 signatures (SHA-512 or SHA-256) | a Kerberos service ticket with an AES session key |
| Role | initiator (client) only | initiator (client) only |

Anything else the server selects is refused with `SncError`. Suite `0x0008` (Kerberos
with AES-128), RSA key transport, other curves and the older token formats are not
implemented.

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

## Kerberos key exchange

Selected with `snc_kerberos` (see the cookbook). The partner name has the form
`p:CN=<name>@<REALM>`. The client asks for a service ticket for, in order:

1. `SAP/<name>@<REALM>` (name type NT-SRV-INST) — what SAP's own Kerberos SNC client
   requests: with partner `CN=A4H@<REALM>` its TGS-REQ named `SAP/A4H`, and with
   partner `CN=sap-snc@<REALM>` it asked for `SAP/sap-snc` (observed on the wire
   2026-11-11, CommonCryptoLib 8.5.5 on Windows).
2. `<name>@<REALM>` itself, when the KDC answers the first with
   `KDC_ERR_S_PRINCIPAL_UNKNOWN` (or Windows cannot get it). Active Directory issues
   tickets for a service account's own name, so `p:CN=<account>@<REALM>` works too
   (observed live).

A `<name>` that already has an instance (`p:CN=SAP/A4H@<REALM>`) is used as written.
Any other KDC refusal is final. See [kerberos.md](kerberos.md) for where the ticket
comes from.

### Message flow

```
Client                                          Server
 token 1  ClientHello, KeyExchangeKey,
          KeyTransport                      ──►
 token 2                                    ◄──  ServerHello, Finished
 token 3  Finished                          ──►
          (SNC frame type 5, ACCEPT_ACK)    ◄──
```

`gss_init_sec_context` semantics: CONTINUE_NEEDED after token 1, then COMPLETE **with**
token 3 as its output. The acceptor completes on token 3 without an output token, and the
SNC layer answers with an empty ACCEPT_ACK frame (type 5, see [snc.md](snc.md)) that the
client must read before it sends data; data sent earlier is refused by the gateway.
There is no AuthRequest or AuthResponse.

### ClientHello

As for X.509, except the key-exchange list is `01` (Kerberos) and extension 3 offers
suite `00 07` only. Live, the server answered with ServerHello `01 01 0007 00004000`
(version 1.1, suite `0x0007`, chunk size 16384).

### KeyExchangeKey and KeyTransport

```
A3 { A0 { OCTET STRING Ticket } }       -- the RFC 4120 Ticket, [APPLICATION 1] DER, as issued
A6 { 81 <ciphertext> }
```

- The ticket is sent as the KDC issued it. No authenticator, AP-REQ or GSS-API
  Kerberos framing is involved.
- Pre-master secret = 48 bytes: `01 01` (the protocol version offered), then 46 random
  bytes.
- `ciphertext` = RFC 3961 encryption of the pre-master secret with the ticket's session
  key, **key usage 2** (for AES: confounder, CBC with ciphertext stealing, HMAC-SHA1-96 —
  76 bytes).

The client proves it holds the session key by this encryption; the server proves it
could decrypt the ticket (and so holds the service key) by producing a valid Finished.

### Key schedule and Finished

The same as for X.509, with the 48-byte pre-master secret above. The transcript is the
concatenation of the handshake messages as sent: the **server's** Finished comes first
and covers ClientHello, KeyExchangeKey, KeyTransport and ServerHello; the client's covers
those plus the server's Finished element. The record layer is identical to suite
`0x0009`.

### Client identity on the server

CommonCryptoLib as acceptor reported the peer name `CN=ALICE@EXAMPLE.COM` for a ticket
issued to `alice@EXAMPLE.COM`: the user part is upper-cased (fixture
`secgss_kerberos_loopback.json`). The SAP user is then found through its SNC name
(`p:CN=<USER>@<REALM>` in SU01).

### Reference client: protocol version 1.0

SAP's own client (CommonCryptoLib 8.5.5 on Windows, NW RFC SDK 7.50) completed a Kerberos
SNC logon against the same system only with protocol version 1.0 offered; offering 1.1
it listed only ECDHE/RSA suites in extension 3 and the server chose ECDHE, which that
client then rejected. It also offered the Kerberos key exchange only when the partner
name carried the prefix `[kerberos]` (`p:[kerberos]CN=A4H@<REALM>`); without it, it
reported "No credentials were supplied". The 1.0 flow it used:

```
Client                                          Server
 token 1  ClientHello (version 1.0)          ──►
 token 2                                    ◄──  ServerHello (1.0, key exchange Kerberos)
 token 3  KeyExchangeKey, KeyTransport,
          Finished                           ──►
 token 4                                    ◄──  Finished
```

The KeyExchangeKey (`A3 { A0 { 04 Ticket } }`) and KeyTransport (`A6 { 81 <76 bytes> }`)
elements had the encoding used above. `saprfclib` implements the 1.1 flow only; the
server accepts both.

### Not verified

- Suite `0x0008` (AES-128): not offered, not implemented.
- Session keys other than AES (RC4, DES): refused by the client. The ticket's own
  encryption type does not matter to the client; the live tickets were RC4-encrypted
  for the service and worked.
- Cross-realm tickets: refused.

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
(HMAC-SHA1/256/512) / AES-256-CBC, or unprotected; PSEs wrapped in local protected storage
(LPS); RSA keys only.

PINs stored by `sapgenpse seclogin` in `SECUDIR/cred_v2` are read in all three forms
`sapgenpse` writes outside Windows: the default (3DES), the AES-256 header form, and LPS.
The first two are keyed on the OS user name the entry was created for; LPS is not.

Which PSE is used when none is named follows CommonCryptoLib: `SECUDIR` (or
`$HOME/sec`), the `cred_v2` entry whose name matches `snc_myname` (case-insensitive,
blanks after commas ignored), else the first entry whose PIN can be recovered, else an
unprotected `SAPSNCS.pse`.

Golden files: `tests/golden/pse/*.pse` (each paired with the key and certificates
`sapgenpse` exported from it) and `tests/golden/pse/cred_*/cred_v2` (each written by
`sapgenpse seclogin` for a known PIN).

Not supported: Windows DPAPI-protected LPS and `cred_v2` entries (host-bound), LPS records
carrying a host or user restriction, EC and EdDSA own keys.

---

## Security notes

- **Not constant-time.** The AES, RSA and ECDH implementations are pure Python. Their
  timing depends on secret data, so a local attacker able to time many operations could
  in principle learn key material. `tlslite-ng` applies RSA blinding to private-key
  operations. Use the built-in mechanism on hosts you control.
- **Performance.** Pure-Python AES runs at roughly a few MB/s; reading a 40 000-row table
  over SNC took 2.4 s in the live test. `tlslite-ng` switches to a native backend
  automatically if one is installed.
- **`cred_v2` and LPS are obfuscation, not protection.** Outside Windows their keys are
  derived from constants and, for `cred_v2`, the OS user name. Anyone who can read the
  `SECUDIR` files can recover the PIN and the private key — this library does exactly that
  to be compatible. Protect `SECUDIR` with file permissions like any private key.
- **Trust anchors are explicit.** Only certificates in the PSE's PK list (or the
  credential's `trusted` tuple) are trusted; there is no system trust store fallback.

---

## Open questions

- Kerberos: the server accepted tickets for `SAP/A4H` and for `sap-snc` (two names of
  one service account, so one key) while its own SNC name was `p:CN=sap-snc@<REALM>`. It
  does not require the ticket's service name to match its SNC name; whether it checks
  anything beyond being able to decrypt the ticket was not tested.

- Which suites besides `0x0009` a server will accept from a client that offers them
  (P-384/P-521 variants, RSA key transport) — not exercised.
- ECDSA own keys and ECDSA server certificates — not exercised.
- Context expiry or re-keying on long-lived sessions — not observed.
