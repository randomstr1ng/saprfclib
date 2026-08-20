# WebSocket RFC

Use WebSocket RFC (wRFC) to connect to SAP BTP ABAP Environment or any S/4HANA system
that exposes the WebSocket RFC endpoint.  The RFC payload is tunnelled over WebSocket/TLS,
so no direct TCP access to the SAP application server is required — only HTTPS port 443.

## Direct wRFC connection to BTP

```python
import saprfclib

# Set wshost to activate the WebSocket RFC transport.
# ashost and sysnr are required positional parameters but are not used for wRFC.
conn = saprfclib.connect(
    ashost="dummy",                 # Not used when wshost is set
    sysnr=0,
    client="100",
    user="YOUR_USER@example.com",
    passwd="secret",
    wshost="your-system.abap.eu10.hana.ondemand.com",
    wsport=443,                     # Default is 443
    ws_path="/sap/bc/rfc?sap-apc-stateful=true",  # Default path
    ws_tls_verify=True,             # Set False only for dev with self-signed certs
)

result = conn.call("STFC_CONNECTION", REQUTEXT="WebSocket RFC call")
print(result["ECHOTEXT"])
print(result["RESPTEXT"])

conn.close()
```

## Via HTTP CONNECT proxy

If your network routes HTTPS traffic through a forward proxy that supports the HTTP CONNECT
method, pass `ws_proxy_host` and `ws_proxy_port` to tunnel the WebSocket connection through it.

```python
import saprfclib

conn = saprfclib.connect(
    ashost="dummy",
    sysnr=0,
    client="100",
    user="YOUR_USER@example.com",
    passwd="secret",
    wshost="your-system.abap.eu10.hana.ondemand.com",
    wsport=443,
    ws_path="/sap/bc/rfc?sap-apc-stateful=true",
    ws_proxy_host="proxy.internal.example.com",
    ws_proxy_port=3128,             # Standard HTTP CONNECT proxy port
    # ws_proxy_user="proxy-user",   # Uncomment if proxy requires auth
    # ws_proxy_pass="proxy-pass",
)

result = conn.call("STFC_CONNECTION", REQUTEXT="via proxy")
print(result["ECHOTEXT"])

conn.close()
```

## Notes

- `wshost` is the **only** activation switch for the WebSocket transport.  When it is set,
  `ashost`/`saprouter`/`mshost` are ignored.
- `ws_tls_verify=False` disables TLS certificate verification — use only in development
  environments with self-signed or expired certificates.  Never use in production.
- The SAP BTP ABAP Environment default path is `/sap/bc/rfc?sap-apc-stateful=true`.
  On-premise systems may use a different ICF node path configured in transaction SICF.
- wRFC uses the same `conn.call()` API as classic TCP RFC — only the transport differs.
- SNC and wRFC cannot be combined in the same connection (SNC-over-wRFC is out of scope
  for the current release).
