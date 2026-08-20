# Connection Options

`saprfclib.connect()` supports five transport modes. All modes share the same
`conn.call()` / `conn.close()` interface once connected.

## Direct TCP (application server)

Connect directly to an SAP application server by hostname and system number.
The gateway port is calculated as `3300 + sysnr`.

```python
conn = saprfclib.connect(
    ashost="10.0.1.5",
    sysnr=0,          # Gateway port = 3300 + sysnr
    client="100",
    user="USER",
    passwd="pass",
    timeout=30.0,     # Socket timeout in seconds (optional)
)
```

## SAProuter hop

Route the connection through an SAProuter when the SAP system is not directly
reachable. The `saprouter` parameter accepts a router string in SAP NI format.

```python
conn = saprfclib.connect(
    ashost="internal-sap-host",
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    saprouter="/H/saprouter.example.com/S/3299/H/sap-host",
)
```

## Message server (load-balanced)

Connect to a logon group via the SAP message server. The message server returns
the least-loaded application server, and saprfclib connects to it directly.

```python
conn = saprfclib.connect(
    ashost="dummy",           # Required positionally; ignored when mshost is set
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    mshost="sapms.example.com",
    sysid="A4H",
    group="PUBLIC",
)
```

## SNC (X.509 / Kerberos)

Use SAP Secure Network Communications for encrypted and mutually authenticated
connections. Set `snc_lib` to the path of your SNC library
(e.g. SAP CommonCryptoLib `libsapcrypto.so`).

```python
conn = saprfclib.connect(
    ashost="sap-host",
    sysnr=0,
    client="100",
    user="USER",
    passwd="",                # Empty when SNC provides auth
    snc_lib="/usr/sap/sapcryptolib/libsapcrypto.so",
    snc_partnername="p:CN=SAPserver, O=Example, C=DE",
    snc_myname="p:CN=myclient, O=Example, C=DE",  # optional
    snc_qop=3,                # 1=auth, 2=integrity, 3=privacy (default)
)
```

| `snc_qop` | Protection level |
|-----------|-----------------|
| 1 | Authentication only |
| 2 | Authentication + integrity |
| 3 | Authentication + integrity + privacy (encryption) |

## WebSocket RFC (BTP / Cloud)

Connect to SAP BTP ABAP Environment or other cloud systems via WebSocket RFC
(RFC over WebSocket over TLS). Use `wshost` instead of `ashost`.

```python
conn = saprfclib.connect(
    ashost="dummy",           # Not used for wRFC; required positionally
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    wshost="my-system.abap.eu10.hana.ondemand.com",
    wsport=443,               # default 443
    ws_path="/sap/bc/rfc?sap-apc-stateful=true",  # default
    ws_tls_verify=True,       # set False for self-signed certs (dev only)
)
```

To route the WebSocket connection through an HTTP CONNECT proxy:

```python
conn = saprfclib.connect(
    ashost="dummy",
    sysnr=0,
    client="100",
    user="USER",
    passwd="pass",
    wshost="my-system.abap.eu10.hana.ondemand.com",
    ws_proxy_host="proxy.internal.example.com",
    ws_proxy_port=3128,
)
```
