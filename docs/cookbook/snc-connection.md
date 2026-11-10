# SNC Connection

SNC (Secure Network Communications) encrypts the RFC connection and authenticates both
ends, with X.509 certificates or with Kerberos tickets. `saprfclib` speaks SAP's SNC
mechanism itself in both variants, so no SAP library is needed. If you already run CommonCryptoLib (or another GSS-API library),
you can still use it through `snc_lib`.

## Built-in SNC (no SAP library)

You need a PSE file with your client key and certificate, and the server's certificate
in that PSE's trusted list. `sapgenpse` creates both:

```bash
sapgenpse get_pse -p client.pse -x <pin> "CN=my-client, O=MyOrg, C=DE"
sapgenpse maintain_pk -a server.crt -p client.pse -x <pin>      # trust the SAP server
sapgenpse export_own_cert -o client.crt -p client.pse -x <pin>  # import into STRUST (SNC SAPCryptolib)
```

```python
import saprfclib

conn = saprfclib.connect(
    ashost="sap-host",
    sysnr="00",
    client="100",
    user="ALICE",
    passwd="...",                   # sent inside the encrypted channel
    snc_partnername="p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE",
    snc_pse="/secure/client.pse",
    snc_pse_pin="...",
)
print(conn.call("RFC_SYSTEM_INFO")["RFCSI_EXPORT"]["RFCSYSID"])
conn.close()
```

- `snc_partnername` must be the server certificate's **complete** subject, most specific
  RDN first. `p:CN=A4H` alone is rejected when the certificate has more RDNs. Letter case
  and spaces after commas do not matter; RDN order does.
- The port defaults to the secure gateway port `48NN`. Pass `port=` if yours differs.
- Instead of a PSE file you can pass `snc_credential=SncCredential(private_key=...,
  certificate_chain=(...,), trusted=(...,))` built from DER bytes you load yourself.
- `snc_myname` is optional; when given it must name the PSE's own certificate.

An existing CommonCryptoLib setup works unchanged. With `SECUDIR` set (or `~/sec`) and a
PIN stored by `sapgenpse seclogin`, the partner name is enough:

```python
conn = saprfclib.connect(ashost="sap-host", sysnr="00", client="100",
                         user="ALICE", passwd="...",
                         snc_partnername="p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE")
```

The PSE is chosen as CommonCryptoLib chooses it (the `cred_v2` entry matching
`snc_myname`, else the first usable one). `snc_pse=` without `snc_pse_pin=` also takes the
PIN from `cred_v2`.

Supported: RSA client keys; PSE files protected with the default or PBES2 encryption,
in local protected storage, or unprotected; `cred_v2` in all forms written outside
Windows. Not supported yet: Windows DPAPI protection, EC client keys.

## Kerberos SNC (single sign-on with Active Directory)

When the SAP system accepts Kerberos SNC (an SNC keytab for its service account in
`SAPSNCSKERB.pse`), a Kerberos ticket replaces the client certificate, and with
`snc_sso=True` the logon needs no password: the SAP user is the one whose SNC name is
`p:CN=<USER>@<REALM>`.

```python
import saprfclib

# The ticket cache left by kinit or a domain login (KRB5CCNAME, else /tmp/krb5cc_<uid>).
conn = saprfclib.connect(
    ashost="sap-host", sysnr="00", client="100",
    snc_partnername="p:CN=sap-snc@EXAMPLE.COM",   # the SAP service account's principal
    snc_kerberos=True,
    snc_sso=True,
)
```

Other ways to get the ticket:

```python
from saprfclib.krb5 import KerberosLogin

# Password: asks the KDC for a ticket itself.
login = KerberosLogin(principal="alice@EXAMPLE.COM", password="...", kdc="dc1.example.com")
# Keytab (a service user without a password prompt).
login = KerberosLogin(principal="alice@EXAMPLE.COM", keytab="/secure/alice.keytab",
                      kdc="dc1.example.com")
# A specific ticket cache file.
login = KerberosLogin(ccache="/tmp/krb5cc_alice", kdc="dc1.example.com")

conn = saprfclib.connect(ashost="sap-host", sysnr="00", client="100",
                         snc_partnername="p:CN=sap-snc@EXAMPLE.COM",
                         snc_kerberos=login, snc_sso=True)
```

- `snc_partnername` is `p:CN=` followed by the principal the SAP system's keytab holds
  (the name used with `sapgenpse keytab -a`). An SPN form such as
  `p:CN=SAP/A4H@EXAMPLE.COM` works as well when that SPN belongs to the same account.
- `kdc=` is needed whenever a ticket has to be requested: always for a password or
  keytab, and for a cache that does not already hold a ticket for the SAP service. Without
  it, the `kdc` entries of the realm in `krb5.conf` are used; if there are none, the call
  fails and says so.
- Only `FILE:` ticket caches can be read. Caches kept in the kernel keyring, by KCM
  (`sssd-kcm`) or by Windows (LSA) are not reachable from Python; use a password or
  keytab login, or point `KRB5CCNAME` at a file cache (`default_ccache_name =
  FILE:/tmp/krb5cc_%{uid}` in `krb5.conf`).
- `snc_myname` is optional; when given it must be `p:CN=<your principal>`.
- Encryption: AES only (`aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`), the Active
  Directory default. Accounts limited to RC4 or DES are refused. The SAP service account's
  own ticket encryption (often RC4) does not matter to the client.
- `connect_async()` accepts the same parameters.

See [Kerberos](../protocol/kerberos.md) and
[SNC mechanism](../protocol/snc-mechanism.md#kerberos-key-exchange) for the details.

!!! warning "Security"
    The built-in cryptography is pure Python and not constant-time. Run it on hosts you
    control. `cred_v2` and LPS (outside Windows) only obfuscate the PIN: anyone who can
    read `SECUDIR` can recover it. Protect `SECUDIR` like a private key.

## Logon with the certificate (no password)

If the SAP user has the client certificate's SNC name maintained (SU01 → SNC), log on
with the SNC identity alone:

```python
conn = saprfclib.connect(
    ashost="sap-host", sysnr="00", client="100",
    snc_partnername="p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE",
    snc_pse="/secure/client.pse", snc_pse_pin="...",
    snc_sso=True,          # user is optional; a password, if given, is not sent
)
```

`snc_sso` defaults to `False` in saprfclib. The NW RFC SDK (and so pyrfc) defaults
`SNC_SSO` to on, which means a password passed there is silently ignored.

## Native GSS library

```python
conn = saprfclib.connect(
    ashost="sap-host",
    sysnr="00",
    client="100",
    user="ALICE",
    passwd="...",
    snc_lib="/usr/sap/sapcryptolib/libsapcrypto.so",   # absolute path
    snc_partnername="p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE",
    snc_myname="p:CN=my-client, O=MyOrg, C=DE",         # optional
)
```

The library finds its own credentials (for CommonCryptoLib: `SECUDIR` and `cred_v2`).

## Quality of protection

| `snc_qop` | Level |
|-----------|-------|
| 1 | Authentication only |
| 2 | Integrity |
| 3 | Privacy (default) |
| 8 | System default |
| 9 | Maximum available |

The server can raise the level: a system configured with
`snc/data_protection/min = 3` encrypts every message regardless of what the client asks
for.

## Notes

- SNC and WebSocket RFC (`wshost`) cannot be combined in one connection.
