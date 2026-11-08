# SNC Connection

SNC (Secure Network Communications) encrypts the RFC connection and authenticates both
ends with X.509 certificates. `saprfclib` speaks SAP's X.509 SNC mechanism itself, so no
SAP library is needed. If you already run CommonCryptoLib (or another GSS-API library),
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

Supported: RSA client keys; PSE files protected with the default or PBES2 encryption, or
unprotected. Not supported yet: reading the PIN from a `cred_v2` file
(`sapgenpse seclogin`), PSEs in local protected storage, EC client keys.

!!! warning "Security"
    The built-in cryptography is pure Python and not constant-time. Run it on hosts you
    control. Keep the PSE file and its PIN as protected as any private key.

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
