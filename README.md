# saprfclib - Pure Python SAP RFC Protocol Implementation

[![CI](https://github.com/randomstr1ng/saprfclib/actions/workflows/ci.yml/badge.svg)](https://github.com/randomstr1ng/saprfclib/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/saprfclib.svg)](https://pypi.org/project/saprfclib/)
[![Python](https://img.shields.io/pypi/pyversions/saprfclib.svg)](https://pypi.org/project/saprfclib/)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen.svg)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16017/badge)](https://www.bestpractices.dev/projects/16017)

`saprfclib` is a pure-Python reimplementation of the SAP RFC wire protocol - zero
native/C dependencies. Call any SAP function module from Python with just a `pip install`.
Supports direct TCP, SAProuter, message server (load-balanced), SNC (X.509 and Kerberos/Active Directory SSO, built in — no SAP library needed),
and WebSocket RFC (SAP BTP/cloud) connections. Requires Python 3.12 or later.

No SAP NetWeaver RFC SDK. No C compiler. No `LD_LIBRARY_PATH`. No container image built
around a proprietary `.so`.

## Installation

```bash
pip install saprfclib
```
Pulls five pure-Python dependencies: `wsproto` and `h11` (WebSocket RFC), and
`asn1crypto`, `ecdsa` and `tlslite-ng` (built-in SNC).

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
it in-process - no configuration needed. After a function module changes in SAP, call
`conn.invalidate_metadata()` and `conn.reset_server_context()` (a pool does both for you).


## Connection Options

| Mode | Key Parameters |
|------|---------------|
| Direct TCP | `ashost`, `sysnr` |
| SAProuter | `ashost`, `sysnr`, `saprouter="/H/router/S/3299/H/target"` |
| Message server | `mshost`, `sysid`, `group` |
| SNC (X.509, built in) | `snc_partnername`, `snc_pse`, `snc_pse_pin` (or `snc_lib` for a native GSS library) |
| SNC (Kerberos SSO, built in) | `snc_partnername="p:CN=<name>@<REALM>"`, `snc_kerberos=True` (Windows logon session or ticket cache) or `saprfclib.krb5.KerberosLogin(...)`, `snc_sso=True` |
| WebSocket RFC | `wshost`, `wsport`, `ws_path` |
| SOCKS5 proxy (SAP BTP) | `proxy_type="socks5"`, `proxy_host`, `proxy_port` (+ `proxy_jwt` / OAuth triple) |

Reach an on-premise system through the SAP BTP Connectivity Proxy / Cloud Connector
(e.g. from a Kyma workload) with no NW RFC SDK or Transparent Proxy:

```python
# trusted mode (no proxy authentication)
conn = saprfclib.connect(
    ashost="s4-2025-raw", sysnr="00", client="001", user="Developer", passwd="...",
    proxy_type="socks5",
    proxy_host="connectivity-proxy.kyma-system.svc.cluster.local",
    proxy_port=20004,
    gwhost="vhcala4hci",  # SAP system's internal host (ashost is the virtual tunnel host)
)

# untrusted mode — SAP JWT (method 0x80), token fetched via client_credentials
conn = saprfclib.connect(
    ashost="s4-2025", sysnr="00", client="001", user="Developer", passwd="...",
    proxy_type="socks5", proxy_host="...", proxy_port=20004,
    proxy_client_id="...", proxy_client_secret="...",
    proxy_token_url="https://<subaccount>.authentication.<region>.hana.ondemand.com/oauth/token",
    proxy_scc_location_id="MyLocation",  # optional Cloud Connector location
)

# or let saprfclib read the bound Connectivity service (VCAP_SERVICES / SERVICE_BINDING_ROOT)
cfg = saprfclib.connectivity_proxy_kwargs()           # add with_auth=False in trusted mode
conn = saprfclib.connect(ashost="s4-2025", sysnr="00", client="001",
                         user="Developer", passwd="...", **cfg)
```

See the [Connection Options guide](https://randomstr1ng.github.io/saprfclib/getting-started/connection-options/)
for the full parameter reference.

## What works, and what doesn't

Every feature is in one of four groups. **Supported** means verified against a live SAP
system — a capture, a golden fixture under `tests/golden/` or an integration test.
**Preview** means implemented and tested offline, but not verified live, or verified with
documented open gaps; it may change in a minor release. **Not implemented** means there
is no such option yet. **Refused** means the library recognises the case and raises a
clear error rather than sending or returning something unverified. The public API
carries the same labels (`tests/api/public_api.json`).

**Supported**

| Capability | Notes |
|---|---|
| Direct logon with password (`ashost`, `sysnr`) | Kernels 793 and 916 |
| Calls with scalar, structure and table parameters; DDIC metadata | |
| ABAP types CHAR, NUM, DATE, TIME, INT1/2/4/8, FLOAT, packed (BCD), DECFLOAT16/34, STRING, XSTRING, UTCLONG | Packed rounding and every sign nibble as the reference client reads them |
| Compressed tables (SAPCOMPRESS LZH) | |
| XML table text (`ET_DATA` with `USE_ET_DATA_4_RETURN`) | |
| Deep structures (STRING, XSTRING, nested structures and tables) and table-typed IMPORTING/EXPORTING/CHANGING parameters | Kernel 916: calls, `RfcServer`, tRFC and qRFC units; tables of elementary rows; namespaced component names. Sent and read as XML like the reference SDK (`docs/protocol/serialization.md`) |
| Connection pool, sync and async; `connect_async()` | `reset_on_release=True` resets ABAP session state between borrowers; waiters served in arrival order, `max_waiters` sheds overload |
| `invalidate_metadata()` on a connection, a pool or a `MetadataCache` | Explicit only: nothing on the wire marks a cached interface as stale (`docs/protocol/framing.md`) |
| Call arguments copied before sending; `CallLimits` bounds on rows and value size | Checked before anything is encoded |
| `reset_server_context()` and `conn.transaction()` (BAPI commit / rollback) | |
| Message server / group logon (`mshost`) | Binary and HTTP resolution |
| SAProuter, including chained routers | |
| SOCKS5 / SAP BTP Connectivity proxy without proxy authentication | |
| WebSocket RFC (`wshost`) | Calls; tRFC over WebSocket is refused |
| Built-in SNC with X.509 (`snc_pse`), RSA and EC (P-256) client keys | Server certificates with EC keys are tested by loopback only |
| Built-in SNC with Kerberos (`snc_kerberos`), including Windows logon-session tickets | AES enctypes only |
| SNC through an external GSS-API library (`snc_lib`) | |
| SNC single sign-on (`snc_sso=True`) | |
| RFC server: registration and inbound calls (`RfcServer`, `AsyncRfcServer`) | Plain TCP |
| tRFC and qRFC submit, with durable TID stores | A retry resends on the same connection (#75) |

**Preview**

| Capability | Why |
|---|---|
| SOCKS5 proxy authentication with a JWT (method `0x80`), message-server logon through the proxy | Not verified live (`docs/protocol/socks5.md`) |
| bgRFC submit and unit stores | The submit payload (SDATA) is not implemented (#34) |
| RFC types 33–40 (UTCSECOND … CDAY) | No system exposes them; widths `[ASSUMED]` |
| SAP LZ4 frames, LZC compression on send | Frame layout `[ASSUMED]`; no capture of a client sending LZC |
| SDK-format traces (`RfcTrace`) | Tested offline only |
| Inbound tRFC in server mode | The parameter block (`0x5001`) is parsed from an `[ASSUMED]` layout; no committed capture (`docs/protocol/trfc.md`) |

**Not implemented**

| Capability | Tracked in |
|---|---|
| SNC on the server side (acceptor role) | `docs/protocol/snc.md` |
| SAP logon tickets (`MYSAPSSO2`) | #78 |
| Client-side callbacks (`DESTINATION 'BACK'`) | #79 |
| Cancelling a call in flight | #82 |

**Refused on purpose**

| Capability | Why |
|---|---|
| Non-Unicode and big-endian systems | Refused at logon: the character handling has never been validated against one (#48) |
| SAP's binary BASXML (`BXML`) | Refused with `NotImplementedError` (#18) |
| RFC types NULL, ABAPOBJECT, XMLDATA | Not serialised |
| Kerberos RC4/DES enctypes, cross-realm tickets; SNC with DSA or EdDSA keys | Refused with a clear error (`docs/protocol/kerberos.md`, `docs/protocol/snc-mechanism.md`) |

CI runs the offline suite on CPython 3.12–3.15 (Linux), 3.12 and 3.15 (Windows, macOS)
and the free-threaded 3.15t build (Linux). Live verification is done against the
maintainer's own systems and recorded as captures; see [SUPPORT.md](SUPPORT.md).

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
| `examples/08_read_table.py` | RFC_READ_TABLE with every TABLE parameter |
| `examples/09_bapi_user_create.py` | BAPI structures and return tables |
| `examples/10_snc_kerberos_sso.py` | Kerberos SNC single sign-on (Active Directory) |

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
