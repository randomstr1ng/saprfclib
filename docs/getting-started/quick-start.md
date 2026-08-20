# Quick Start — 10 Minutes to First Call

## 1. Install

```bash
pip install saprfclib
```

## 2. Connect

```python
import saprfclib

conn = saprfclib.connect(
    ashost="your-sap-host",   # Application server hostname or IP
    sysnr=0,                  # System number (int or str; port = 3300 + sysnr)
    client="100",             # SAP client (Mandant)
    user="RFC_USER",          # SAP logon user
    passwd="secret",          # Password (never logged by saprfclib)
)
```

## 3. Call STFC_CONNECTION

```python
result = conn.call("STFC_CONNECTION", REQUTEXT="Hello from saprfclib!")
print(result["ECHOTEXT"])    # "Hello from saprfclib!"
print(result["RESPTEXT"])    # SAP server's response text
```

`conn.call()` fetches the function module's metadata from DDIC automatically
on the first call and caches it in-process. Subsequent calls to the same
function skip the metadata fetch.

## 4. Read connection attributes

```python
attrs = conn.get_connection_attributes()
print(attrs.sys_id)          # SAP System ID (e.g. "A4H")
print(attrs.partner_host)    # App server hostname
print(attrs.unicode_mode)    # True for Unicode systems
```

## 5. Close the connection

```python
conn.close()
```

`close()` is safe to call in any state, including after an error.

## 6. Handle errors

```python
try:
    result = conn.call("STFC_CONNECTION", REQUTEXT="test")
except saprfclib.AbapApplicationError as exc:
    # ABAP raised an application exception (e.g. incorrect input)
    print(f"Application error: key={exc.key} message={exc.message}")
except saprfclib.AbapSystemFailure as exc:
    # ABAP short dump or system failure
    print(f"System failure: {exc.message}")
except saprfclib.CommunicationError as exc:
    # Network or protocol failure
    print(f"Communication error: {exc.message}")
except saprfclib.SapRfcError as exc:
    # Catch-all for any saprfclib error
    print(f"RFC error: {exc}")
finally:
    conn.close()
```

## Next steps

- [Connection Options](connection-options.md) — direct TCP, SAProuter, message server, SNC, WebSocket RFC
- [Error Handling](error-handling.md) — full exception hierarchy and patterns
- [Cookbook](../cookbook/index.md) — recipes for TABLE parameters, connection pools, tRFC, and more
