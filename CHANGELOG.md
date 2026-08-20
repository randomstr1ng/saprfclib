# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial public release of the pure-Python SAP RFC protocol implementation.
  - ABAP type codec covering the RFCTYPE surface (CHAR, NUM, DATE, TIME, BCD,
    FLOAT, INT/INT1/INT2/INT8, BYTE, XSTRING, STRING, STRUCTURE, TABLE,
    DecFloat16/34, UTCLONG, UTCSECOND, UTCMINUTE, DTDAY, DTWEEK, DTMONTH, TSECOND,
    TMINUTE, CDAY).
  - NI/TCP transport, sans-I/O session state machine, and logon handshake.
  - Synchronous RFC client with DDIC metadata introspection and caching.
  - RFC server: gateway registration and inbound call dispatch.
  - Thread-safe bounded connection pool.
  - tRFC / qRFC / bgRFC with pluggable durable stores.
  - SNC (X.509 / Kerberos) via a user-supplied GSS-API library.
  - WebSocket RFC (SAP BTP / cloud) over `wsproto` + `h11`.
  - SAProuter route strings and message-server group logon.
  - Async-native client, pool, and server APIs.
  - Wire-protocol documentation and byte-exact golden fixture test suite.

### Changed

- Project relicensed from MIT to **MPL-2.0** before first public release.
- Distribution and import name are `saprfclib`. The name `saprfc` on PyPI belongs to
  an unrelated, long-abandoned project.

[Unreleased]: https://github.com/randomstr1ng/saprfclib/commits/main
