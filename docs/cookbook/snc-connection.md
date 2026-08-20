# SNC Connection

Use SNC (Secure Network Communications) to establish an encrypted and optionally
certificate-authenticated connection to an SAP system without sending user credentials
over the wire.  Pass `snc_lib` pointing to your GSS-API provider library (e.g.
CommonCryptoLib `libsapcrypto.so`) and `snc_partnername` identifying the SAP server.

## X.509 SNC connection

```python
import saprfclib

# snc_lib presence activates SNC.  The path must point to a GSS-API provider
# shared library, typically SAP's CommonCryptoLib (libsapcrypto.so on Linux).
conn = saprfclib.connect(
    ashost="sap-host",
    sysnr=0,
    client="100",
    user="",                        # Empty string: certificate provides the identity
    passwd="",                      # Empty string: SNC provides authentication
    snc_lib="/usr/sap/sapcryptolib/libsapcrypto.so",
    snc_partnername="p:CN=A4H, OU=SAP, O=SAP SE, C=DE",   # SAP server's SNC name
    snc_myname="p:CN=myclient, O=MyOrg, C=DE",             # Client SNC name (optional)
    snc_qop=3,                      # Quality of protection: 3 = privacy (encrypt + auth)
)

result = conn.call("STFC_CONNECTION", REQUTEXT="SNC-encrypted call")
print(result["ECHOTEXT"])
print(result["RESPTEXT"])

conn.close()
```

## Quality of Protection levels

| `snc_qop` | Level | Description |
|-----------|-------|-------------|
| 1 | Authentication | Verifies peer identity only; data is not encrypted |
| 2 | Integrity | Authentication + message integrity check (no encryption) |
| 3 | Privacy (default) | Authentication + integrity + full encryption |

## Notes

- `snc_lib` must be the **absolute path** to the shared library — a relative path is
  not portable across working-directory changes.
- `snc_partnername` must match the Distinguished Name configured in the SAP system's
  SNC settings (transaction SNC0 / STRUST).
- When SNC provides the authentication (certificate-based), `user` and `passwd` can be
  empty strings.  The GSS-API library derives the identity from the client certificate.
- `snc_myname` is optional; if omitted the library uses the default identity configured
  in the GSS-API provider.
- SNC and wRFC (`wshost`) cannot be combined in the same connection (SNC-over-wRFC is
  out of scope for the current release).
