# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `connect()` and `connect_async()` accept `lang`, the logon language. Takes either the
  one-character SAP code (`"E"`) or the two-character ISO code (`"EN"`), matching the `LANG`
  option of the SAP NetWeaver RFC SDK. The logon frame carries one character on TLV tags
  0x0011 and 0x0115 either way; an ISO code is converted first (#8).
- `saprfclib.language_iso_to_sap()` and `saprfclib.language_sap_to_iso()` convert between the
  two forms, matching the helper names `pyrfc` exposes. Unlike the C SDK's forward conversion,
  an unrecognised code raises `ValueError` instead of returning an undefined character.

### Fixed

- **TABLES parameters are no longer mistyped as structures.** `RFC_GET_FUNCTION_INTERFACE`
  declares a TABLES param with the `EXID` of its row structure, so typing from `EXID` alone
  gave every TABLES param `RFCTYPE_STRUCTURE`. Requests then emitted the scalar
  0x0201/0x0203 pair and the server rejected the call with `CALL_FUNCTION_ILLEGAL_P_TYPE`;
  responses decoded concatenated row bytes as a single work area and dropped every row past
  the first. `PARAMCLASS='T'` now decides the type. Affects every function module with
  TABLES parameters — `RFC_READ_TABLE`, `BAPI_USER_GET_DETAIL`, and so on (#9, #10).
- The metadata bootstrap now fetches the row layout for TABLE parameters as well as
  STRUCTURE parameters, so a correctly typed TABLES param reaches the encoder with its
  `type_desc` attached instead of failing to encode its rows (#12).
- Structure and table rows may be supplied as partial dicts. Fields the caller omits are
  encoded at their type's initial value — blank-padded for character fields, zero-padded
  for numeric — instead of raising `KeyError`. This is how most SAP function modules expect
  to be called; `RFC_READ_TABLE`'s `FIELDS` rows are the common case (#11).
- `ping()` works against live systems. Two independent defects (#7):
  the RFCPING **request** was sent as a bare TLV body with no gateway framing, so the
  server read the function name where it expected a 76-byte GW header and answered with a
  plain-text error; and the **response** parser did not strip the gateway frame header,
  did not handle extended-length records, and did not skip the repeated close tag that
  follows each record — the last of which desynchronised the walk by two bytes and misread
  every subsequent tag. The probe is now built through the same capture-confirmed invoke
  path as any other call, and both frames are now golden fixtures
  (`tests/golden/framing/rfcping_request.bin`, `rfcping_response.bin`) captured from a
  live kernel 793 system.

- **Function metadata for large function modules is now readable at all.** The server
  sends a table SAPCOMPRESS-compressed under tag `0x0305` once it exceeds roughly 8 KB,
  and the reader accepted only uncompressed `0x0303` rows — so every function module
  with enough parameters produced an empty `FunctionDesc` with no diagnostic. This
  affects most BAPIs, `BAPI_USER_GET_DETAIL` among them. Compressed tables are now
  decompressed (the `0x0305` records are fragments of one stream, not independent
  blocks) and sliced by the row size the server declares rather than a hardcoded 402,
  which is required because the compressed form uses a padded stride.
- **The RFC server serialized TABLE outputs as scalar values.** Every output parameter
  was emitted as a `0x0201`/`0x0203` pair, tables included — the server-direction twin
  of the client-side mistyping that produced `CALL_FUNCTION_ILLEGAL_P_TYPE`. Tables now
  use the table protocol (`0x0301`/`0x0330`/`0x0302`/`0x0304`), matching the shape a
  real SAP server uses in the golden captures.
- Structure and table layouts that failed to resolve now raise a `ValueError` naming the
  parameter and explaining that the `RFC_GET_STRUCTURE_DEFINITION` lookup did not
  complete, instead of a bare `AssertionError` naming nothing. Assertions also vanish
  under `python -O`, which turned the same condition into a corrupt encode.
- Failures to fetch a DDIC type layout are logged at WARNING instead of being discarded.
- A metadata response that yields no parameter rows is now logged at WARNING instead
  of silently producing an empty descriptor.
- **Table parameters no longer abort the connection.** A request carrying table rows
  emitted a `0x0306` end tag that the SAP RFC SDK never writes and no capture contains.
  The server responded by tearing down the gateway conversation: the call returned an
  80-byte header-only frame and every later call on that connection failed with
  "Conversation NNN not found". Verified live on kernel 793 — removing the tag is the
  single change that turns the failure into a success.
- Tables the caller passes as input are returned by the server under `0x0335`/`0x0336`,
  identified by the DM table ID the client assigned in `0x0330` rather than by name.
  These were previously unrecognised, so such parameters were missing from the result.
- Parameter widths from `RFC_GET_FUNCTION_INTERFACE` are no longer double-scaled on a
  Unicode connection. `OFFSET`/`INTLENGTH` already arrive as Unicode byte counts;
  doubling them emitted values at twice their declared width, which the server
  discarded — `RFC_READ_TABLE` raised `TABLE_NOT_AVAILABLE` because `QUERY_TABLE` never
  arrived intact.
- An RFC response carrying no return code now raises `CommunicationError` instead of
  being reported as an empty successful result. An aborted call used to surface much
  later as a missing key in caller code, leaving a dead connection in use.
- Passing a parameter the function interface does not declare now raises `ValueError`.
  The value was previously dropped from the request without any diagnostic, and the
  server ran the function without it.
- Function metadata rows that cannot be parsed are logged at WARNING instead of being
  discarded in silence. `PARAMCLASS='X'` exception rows are now recognised deliberately
  rather than being dropped as a side effect of their blank `EXID`.

## [0.1.0] - 2026-08-20

First public release. Beta: the offline test suite passes against byte-exact golden
fixtures captured from live SAP systems, but the public API may still change before 1.0.

### Added

- Pure-Python implementation of the SAP RFC wire protocol — client and server, with no
  SAP NetWeaver RFC SDK, no C compiler, and no native dependencies.
- ABAP type codec covering the RFCTYPE surface: CHAR, NUM, DATE, TIME, BCD, FLOAT,
  INT/INT1/INT2/INT8, BYTE, XSTRING, STRING, STRUCTURE, TABLE, UTCLONG, UTCSECOND,
  UTCMINUTE, DTDAY, DTWEEK, DTMONTH, TSECOND, TMINUTE, CDAY.
- NI/TCP transport, sans-I/O session state machine, and logon handshake.
- Synchronous RFC client with DDIC metadata introspection and in-process caching.
- RFC server: gateway registration and inbound call dispatch.
- Thread-safe bounded connection pool.
- tRFC / qRFC / bgRFC with pluggable durable stores.
- SNC (X.509 / Kerberos) via a user-supplied GSS-API library, loaded at runtime — no
  install-time dependency.
- WebSocket RFC (SAP BTP / cloud) over `wsproto` + `h11`.
- SAProuter route strings and message-server group logon.
- Async-native client, pool, and server APIs alongside the synchronous facade.
- Wire-protocol documentation and a byte-exact golden-fixture test suite.
- `py.typed` marker — the package ships its type information.

### Known limitations

- **DECFLOAT16 / DECFLOAT34 are not implemented.** The wire encoding is unconfirmed, so
  `encode` and `decode` raise `NotImplementedError` rather than risk silently corrupting
  decimal values. Calling a function module with a DECFLOAT parameter will fail.
- **SNC SSO2 token mode is not supported** — `snc_sso=True` raises
  `NotImplementedError`. Certificate and Kerberos SNC are unaffected, and inbound frames
  carrying extension headers parse correctly.
- **SNC acceptor (server) role is not implemented** — client/initiator only.
- The negative BCD sign nibble and the non-Unicode STRUCTURE offset layout are documented
  but unconfirmed on the wire. See the [protocol
  documentation](https://randomstr1ng.github.io/saprfclib/protocol/serialization/) for the
  full gap list.

### Notes

- Licensed under **MPL-2.0**. Modifications to this project's own files stay open; using
  it inside a closed-source product carries no obligation on your code.
- The distribution and import name is `saprfclib` — `pip install saprfclib`,
  `import saprfclib`. The name `saprfc` on PyPI belongs to an unrelated, long-abandoned
  project and is not this library.
- Not affiliated with or endorsed by SAP SE. See [NOTICE](NOTICE).

[Unreleased]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/randomstr1ng/saprfclib/releases/tag/v0.1.0
