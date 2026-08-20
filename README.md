# saprfclib - Pure Python SAP RFC Protocol Implementation

[![CI](https://github.com/randomstr1ng/saprfclib/actions/workflows/ci.yml/badge.svg)](https://github.com/randomstr1ng/saprfclib/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/saprfclib.svg)](https://pypi.org/project/saprfclib/)
[![Python](https://img.shields.io/pypi/pyversions/saprfclib.svg)](https://pypi.org/project/saprfclib/)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen.svg)](LICENSE)

`saprfclib` is a pure-Python reimplementation of the SAP RFC wire protocol - zero
native/C dependencies. Call any SAP function module from Python with just a `pip install`.
Supports direct TCP, SAProuter, message server (load-balanced), SNC (X.509/Kerberos),
and WebSocket RFC (SAP BTP/cloud) connections. Requires Python 3.12 or later.

No SAP NetWeaver RFC SDK. No C compiler. No `LD_LIBRARY_PATH`. No container image built
around a proprietary `.so`.

## Installation

```bash
pip install saprfclib
```
Pulls two pure-Python dependencies (`wsproto` and `h11`)

## Quick Start

```python
import saprfclib

conn = saprfclib.connect(
    ashost="your-sap-host",   # Application server hostname or IP
    sysnr=0,                  # System number (port = 3300 + sysnr)
    client="100",             # SAP client (Mandant)
    user="RFC_USER",          # SAP logon user
    passwd="secret",          # Password (never logged by saprfclib)
)

result = conn.call("STFC_CONNECTION", REQUTEXT="Hello from saprfclib!")
print(result["ECHOTEXT"])    # "Hello from saprfclib!"
print(result["RESPTEXT"])    # SAP server response text

conn.close()
```

`conn.call()` fetches function module metadata from DDIC on the first call and caches
it in-process - no configuration needed.


## Connection Options

| Mode | Key Parameters |
|------|---------------|
| Direct TCP | `ashost`, `sysnr` |
| SAProuter | `ashost`, `sysnr`, `saprouter="/H/router/S/3299/H/target"` |
| Message server | `mshost`, `sysid`, `group` |
| SNC (X.509 / Kerberos) | `snc_lib`, `snc_partnername`, `snc_qop` |
| WebSocket RFC | `wshost`, `wsport`, `ws_path` |

See the [Connection Options guide](https://randomstr1ng.github.io/saprfclib/getting-started/connection-options/)
for the full parameter reference.

## Documentation

Full documentation: **https://randomstr1ng.github.io/saprfclib/**

- [Getting Started](https://randomstr1ng.github.io/saprfclib/getting-started/installation/) - install,
  connect, and make your first call in 10 minutes
- [Cookbook](https://randomstr1ng.github.io/saprfclib/cookbook/) - TABLE parameters,
  RFC server, tRFC/qRFC, connection pool, SNC, WebSocket RFC
- [API Reference](https://randomstr1ng.github.io/saprfclib/api/connect/) - auto-generated from
  typed docstrings via MkDocs + mkdocstrings
- [Protocol Docs](https://randomstr1ng.github.io/saprfclib/protocol/framing/) - NI/CPIC framing,
  ABAP type serialization, RFC handshake, SNC, tRFC/bgRFC wire specs

## Example Scripts

The `examples/` directory contains runnable scripts for common patterns:

| Script | Pattern |
|--------|---------|
| `examples/01_connect_and_call.py` | Basic connect → call → close |
| `examples/02_table_params.py` | RFC_READ_TABLE with TABLE parameters |
| `examples/03_connection_pool.py` | Multi-threaded connection pool |
| `examples/04_trfc_submit.py` | tRFC / qRFC lifecycle |
| `examples/05_rfc_server.py` | RFC server with handler |
| `examples/06_snc_connection.py` | SNC X.509 connection |
| `examples/07_websocket_rfc.py` | WebSocket RFC to SAP BTP |

All examples read connection parameters from `SAPRFC_*` environment variables.

## Development

```bash
git clone https://github.com/randomstr1ng/saprfclib
cd saprfclib
pip install -e ".[dev]"
```

```bash
# Run offline test suite (no live SAP needed)
hatch run test -m "not integration"

# Lint and format
hatch run lint:check
hatch run lint:fmt

# Type-check
hatch run lint:type

# Build wheel + sdist
hatch build
```

Live integration tests require a running SAP system. Set environment variables:

```bash
export SAPRFC_ASHOST=your-sap-host
export SAPRFC_SYSNR=0
export SAPRFC_CLIENT=100
export SAPRFC_USER=RFC_USER
export SAPRFC_PASSWD=secret
pytest -m integration
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide, and
[CLAUDE.md](CLAUDE.md) for the protocol-fidelity rules every change must follow.


## License

Licensed under the **Mozilla Public License 2.0** - see [LICENSE](LICENSE).

MPL-2.0 is deliberate: you may use `saprfclib` inside a closed-source, commercial
product with no obligation to release your own code. If you modify `saprfclib`'s own
source files, those modified files must remain under MPL-2.0 and be made available.
Improvements to the library flow back; your product stays yours.

## Trademarks and Affiliation

This project is **not affiliated with, endorsed by, or supported by SAP SE**. SAP,
ABAP, SAP NetWeaver, SAProuter, and SAP S/4HANA are trademarks or registered
trademarks of SAP SE in Germany and other countries, used here for identification
only. `saprfclib` contains no SAP code, binaries, or headers. Using it does not grant
you any licence to SAP software - you remain responsible for your own SAP licensing.

See [NOTICE](NOTICE) for details.
