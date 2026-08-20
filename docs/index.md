# saprfclib — Pure Python SAP RFC

A pure-Python reimplementation of the SAP NW RFC wire protocol. Zero native dependencies.
Install with pip and call any SAP function module.

## Features

- **Direct TCP** connection to SAP application servers
- **SAProuter** hop support for network traversal
- **Message server** (load-balanced) connections
- **SNC** (X.509 / Kerberos) encrypted and authenticated connections
- **WebSocket RFC** (wRFC) for SAP BTP ABAP Environment and cloud systems
- **Full ABAP type codec** — CHAR, INT, BCD, DECF16/34, TABLE, STRUCTURE, and more
- **RFC server** — register a Python function as an SAP-callable RFC function module
- **Connection pool** — thread-safe pool with configurable min/max size and acquire timeout
- **tRFC / qRFC / bgRFC** — transactional and queued RFC with TID lifecycle management

## Get Started

See the [Quick Start guide](getting-started/quick-start.md) to make your first SAP function
module call in under 10 minutes.

```python
import saprfclib

conn = saprfclib.connect(
    ashost="your-sap-host",
    sysnr=0,
    client="100",
    user="RFC_USER",
    passwd="secret",
)
result = conn.call("STFC_CONNECTION", REQUTEXT="Hello from saprfclib!")
print(result["ECHOTEXT"])
conn.close()
```
