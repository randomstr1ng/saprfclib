# Kerberos client (`saprfclib.krb5`)

**Status:** CONFIRMED against Active Directory (Windows Server 2022) on 2026-11-10:
pre-authenticated AS exchange with a password and with a keytab, TGS exchange for a
user principal and an SPN, use of tickets from MIT-written credential caches, and Kerberos
SNC logons built on them ([snc-mechanism.md](snc-mechanism.md#kerberos-key-exchange)).
Tickets from the Windows logon session confirmed on Windows 11 on 2026-11-11.
**Implemented in:** `src/saprfclib/krb5/` — `crypto.py`, `messages.py`, `client.py`,
`files.py`, `lsa.py`, `login.py`.
**Evidence:** RFC test vectors and MIT-written files under `tests/golden/krb5/`,
replayed by `tests/test_krb5.py`; live tests behind the `integration` marker.

Unlike the SNC mechanism, Kerberos is a published standard. Everything here follows the
RFCs and the MIT file-format documentation; no value is taken from observation alone.

| Piece | Specification |
|---|---|
| AES encryption and checksums, n-fold, key derivation, string-to-key | RFC 3961, RFC 3962 |
| Messages (AS-REQ/REP, TGS-REQ/REP, AP-REQ, KRB-ERROR), key usages | RFC 4120 |
| PA-PAC-REQUEST | MS-KILE 2.2.3 |
| Credential cache v3/v4, keytab v2 | MIT krb5 documentation, "Credential cache file format", "Keytab file format" |
| Tickets of the Windows logon session | Win32 `LsaCallAuthenticationPackage` with `KerbRetrieveEncodedTicketMessage`; structures from `NTSecAPI.h` |

## Scope

- Encryption types 17 and 18 (`aes128/256-cts-hmac-sha1-96`), checksum types 15 and 16.
  RC4-HMAC (needs MD4), DES, 3DES and the RFC 8009 SHA-2 profiles are not implemented.
- AS exchange with PA-ENC-TIMESTAMP pre-authentication; the salt and iteration count
  always come from the KDC's ETYPE-INFO2.
- TGS exchange in the client's realm. No referrals, cross-realm, FAST, PKINIT,
  S4U or user-to-user.
- KDC transport: TCP with the 4-byte length prefix (RFC 4120 7.2.2). UDP is not used.
- Files: FILE ccache versions 3 and 4, keytab version 2. The native-byte-order versions
  (ccache 1/2, keytab 1) are refused. `KEYRING:`, `KCM:` and `API:` caches are not files
  and cannot be read.
- Windows: the logon session's tickets, through LSA (below).

## Windows logon session

On Windows, with no `KRB5CCNAME` set and no password, keytab or cache given, the ticket
comes from the user's logon session: `LsaConnectUntrusted`, then
`LsaCallAuthenticationPackage` to the `Kerberos` package with a
`KERB_RETRIEVE_TKT_REQUEST` (message type 8, `KerbRetrieveEncodedTicketMessage`) for the
service principal, encryption type 18 and then 17, cache option
`KERB_RETRIEVE_TICKET_CACHE_TICKET`. Windows answers from its cache or asks the domain
controller with the session's ticket-granting ticket, so no KDC address is needed. The
reply's `KERB_EXTERNAL_TICKET` carries the DER ticket and its session key.

Observed on Windows 11 against Active Directory:

- The target name must lie inside the submitted buffer, directly after the request
  structure; a pointer elsewhere is refused with `STATUS_INVALID_PARAMETER`.
- The session key of a service ticket is returned to an ordinary process (only the
  ticket-granting ticket's key is withheld by default, which is not needed).
- A request naming an encryption type gets a newly issued ticket rather than the cached
  one.
- An unknown service principal is reported as `0xC000018B` ("no computer account for
  this workstation trust relationship"), not as an unknown principal; every candidate
  name is therefore tried and all the errors are reported together.

## KDC discovery

`KerberosLogin(kdc=...)` if given, else the realm's `kdc` lines in `krb5.conf`
(`KRB5_CONFIG`, else `/etc/krb5.conf`). DNS SRV lookup is not done (the standard library
has no SRV resolver); with no KDC known the call fails naming the realm.

## Security notes

- The AES implementation is pure Python (`tlslite-ng`) and not constant-time; see the
  notes in [snc-mechanism.md](snc-mechanism.md#security-notes).
- Keys, passwords and tickets never appear in a `repr`, log record or exception message.
- A keytab or a ticket cache is as sensitive as a password; protect it with file
  permissions.
