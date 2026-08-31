# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Python 3.14 is supported and tested. Added to the CI matrix and the package
  classifiers; the suite passes under `-W error` on 3.14, including with random test
  ordering.
- Connections may be opened without credentials. Passing neither `user` nor `passwd`
  (and no `snc_lib`) omits the user and password records from the logon frame rather
  than sending empty ones — an empty password is still a password attempt as far as
  the server is concerned, and repeated attempts against a real account name count
  towards lockout. Supplying exactly one of the two raises `ValueError`, since that is
  a missing setting rather than a request to connect anonymously. WebSocket RFC
  requires credentials and says so, because they travel on the HTTP upgrade.
- CPIC-layer failures are decoded. When a conversation is refused below the RFC layer
  the peer answers in EBCDIC rather than TLV; that used to surface as "the response is
  not a readable RFC message". It now reports the message, e.g.
  `the connection failed below the RFC layer: FREE 1 00024error during logon`.

### Fixed

- `_LoopThread.close()` stopped the background event loop but never closed it, so every
  synchronous classic connection leaked a loop and the file descriptors behind its
  selector until garbage collection. Python 3.14 surfaces this as a `ResourceWarning`;
  the cost was real on every version and accumulated in long-running processes.
- `asyncio.iscoroutinefunction` is deprecated in 3.14 and removed in 3.16; the server
  dispatch path now uses `inspect.iscoroutinefunction`.
- Two test helpers leaked sockets, which made the suite unrunnable with `-W error` and
  attributed the collection to whichever unrelated test was running at the time.
- Multi-row XML-encoded tables are confirmed working and no longer rest on an
  assumption. A ten-row read arrives as ten `<item>` elements split across fragments
  that do not align to item boundaries, which is why they are joined before parsing.
  Cross-checked against the binary path: the identical query without
  `USE_ET_DATA_4_RETURN` returns the same rows field for field.
- Documented that the XML form does not blank-pad fields to their DDIC width, unlike
  the binary encoding — a caller splitting the delimited row gets trimmed values on
  one path and padded values on the other.
- ABAP exceptions from a 7.52 system are now reported with their key and message text.
  That release carries the exception key in `0x0403` and the message in `0x0402`, tags
  that appear in no kernel 793 capture, so both were ignored: an error that says
  `Logon data incomplete.` on the wire reached the caller as
  `AbapApplicationError(key=None, message=None)`. Both spellings are now read, and the
  kernel 793 tags keep priority. Message class, type and number were already correct.
- Exception text is decoded at the width the value actually has. Kernel 793 sends these
  fields as UTF-16LE, the 7.52 system sends them single-byte, and the two are not
  separable by inspecting for high bytes — ASCII in UTF-16LE has none either, and
  decoding it single-byte turns `Logon data incomplete.` into `L o g o n`. The
  interleaved-NUL pattern is what distinguishes them.
- Descriptor caching no longer keys on an empty system ID. A 7.52 logon response carries
  no `0x0450`/`0x0452`/`0x0453` at all, leaving `sys_id` empty; a process holding
  connections to two such systems filed both under `""` and could be served the other
  system's parameter list for a same-named function module — silently, since a
  `FunctionDesc` records no system of origin. An unidentified system now falls back to a
  key unique to the connection, so repeat calls still skip the round-trip and nothing is
  shared across systems. A SID is deliberately *not* reconstructed from the `0x0008`
  instance name; that shape is a naming convention, not a protocol guarantee.
- An empty response frame is no longer reported as a malformed one. A header-only refusal
  (observed on 7.52, where kernel 793 sends an EBCDIC CPIC error instead) has no body to
  be malformed, and saying so pointed at the parser rather than at the server.
- Removed a duplicate, unreachable copy of the system-failure classifier in
  `parse_invoke_response`. `raise_for_rfc_error` runs first and already handles a
  non-zero return code; the second copy could only drift out of step with the one that
  actually runs, and had already begun to.
- Pinned `asyncio_default_fixture_loop_scope` so a `pytest-asyncio` upgrade cannot change
  fixture loop scoping under the suite. Unset, it also aborted any run under `-W error`.
- **bgRFC: a unit that did not run is no longer committed as though it had.** Several
  separate faults produced the same outcome — the server confirmed the LUW and the
  caller believed its work was done:
    - `call_error` was reassigned on every iteration, so a unit whose first call raised
      and whose second succeeded ended the loop with no error and was committed. Whether
      a failure survived depended on nothing but call ordering. Execution now stops at
      the first error, which a unit's all-or-nothing semantics require anyway: the
      caller re-ships the whole unit, so anything run after the failure would run twice.
    - An empty buffered call, one whose name could not be decoded, and one whose name
      was blank each returned "no error" and counted as executed.
    - A frame declaring more calls than it carried skipped the gap and committed a
      partial LUW as a complete one.
    - An unreadable `BGRFC_CALL_COUNT` was treated as zero calls, so the unit committed
      having executed nothing at all.
- bgRFC buffered-call names are found correctly. The scan for the UTF-16LE NUL
  terminator used `bytes.find(b"\x00\x00")`, which matches the low NUL of the final
  character plus the first NUL of the terminator — an odd offset for every ASCII name.
  That was then rejected as unaligned and the entire payload taken as the name, so any
  call carrying parameters resolved to a garbage function name. The terminator is a
  code unit and is now sought on even offsets.
- A bgRFC unit-state lookup that raises no longer answers `NOT_FOUND`. `NOT_FOUND` means
  "never seen", and the caller responds to it by shipping the unit again — so a failing
  lookup against an already-committed unit re-ran the LUW. A failed lookup is now
  reported as a failure.
- bgRFC user callbacks (`on_commit_unit`, `on_rollback_unit`, `on_confirm_unit`) are
  still isolated so a faulty callback cannot take down the server, but they are now
  logged with a traceback instead of discarded. A rollback handler that throws leaves
  the caller's own state half-undone, which is precisely what nobody found out about.
- The unimplemented bgRFC parameter encoding (OG-06-02) says so. A handler was invoked
  with an empty request dict while the call's payload was dropped; that now logs a
  warning naming the function and the number of bytes discarded.
- `AsyncConnectionPool` reports the connections it discarded. `PoolTimeoutError` was
  constructed with `discarded=0` unconditionally, turning the one field that separates
  "the pool is busy" from "the pool is churning dead connections" into a constant.
- The pool logs failed health checks and close errors at DEBUG rather than discarding
  them silently, so a pool binning every connection it checks no longer looks merely slow.
- The SQLite stores refuse a database written by a newer `saprfclib` instead of reading
  and writing it through the older schema they know — on a store whose purpose is
  surviving a crash intact. They also stamp `PRAGMA user_version` from `_SCHEMA_VERSION`
  rather than a repeated literal `1`; the two were independent, so bumping the constant
  would have created a new schema and recorded it as the old version.
- The server logs, at DEBUG, an output parameter its handler did not supply. Skipping it
  is correct — outputs are optional — but the client simply saw the key missing.


## [0.1.2] - 2026-08-28

### Added

- `IncompleteDescriptorError` in the public exception hierarchy (see Fixed, #28).
- `connect(strict_params=...)` and `connect_async(strict_params=...)` control what
  `call()` does with a keyword argument the function interface does not declare.
  The default, `False`, drops it and logs a warning so code ported from `pyrfc` that
  passes a superset of kwargs keeps working; `True` raises `ValueError`. Note that
  both `pyrfc` and the SAP NW RFC SDK raise in this situation — the lenient default is
  a deliberate convenience, and a dropped argument changes what the call does (#24).

### Fixed

- Metadata retrieval no longer treats an ABAP exception as an empty descriptor. A
  function module that is not remote-enabled answers `RFC_GET_FUNCTION_INTERFACE`
  with a normal exception (`FL`/`046`/`FU_NOT_FOUND`), and because an exception reply
  carries no `0x0420` the return-code check never fired — so the descriptor came back
  empty and every subsequent call rejected the caller's arguments as unknown. All four
  metadata bootstraps now classify errors through one shared path (#25).
- The exception tag mapping was wrong. `0x0402`–`0x0408` came from documentation and
  matches no capture; three live exception replies agree on `0x0415` message class,
  `0x0416` type, `0x0417` number and `0x0411` first variable. `AbapApplicationError`
  now carries the full message coordinates instead of only the key.
- A SAP gateway error record is recognised and reported as one. The gateway answers a
  frame it will not process with NUL-separated text rather than TLV; reading that as
  TLV produced `malformed TLV: tag 0x2a45 length 21074`, which says nothing about the
  conversation having been torn down. Any response that is not a readable RFC message
  now raises `CommunicationError` naming what actually arrived (#28).
- New `IncompleteDescriptorError`, raised when a STRUCTURE or TABLE parameter has no
  resolved layout. Distinct from the ABAP errors so a caller can fall back to another
  backend on a metadata gap; subclasses `ValueError` as well, so existing handlers are
  unaffected (#28).
- Tables returned as plain-text XML under `0x3c02`/`0x3c05` are decoded instead of
  being dropped from the result. `RFC_READ_TABLE` uses this for `ET_DATA` when called
  with `USE_ET_DATA_4_RETURN='X'` (#29). SAP's binary BASXML remains unimplemented
  (#18) and is now refused explicitly rather than mis-parsed as text.
- The invoke-frame footer packed the TLV body length as a 16-bit integer, so any
  request body over 64 KB raised `struct.error` — a real ABAP program submitted
  through `/SAPDS/RFC_ABAP_INSTALL_RUN` is enough to hit it. The field is 32-bit;
  verified against all nine request fixtures, whose footers are unchanged (#27).

## [0.1.1] - 2026-08-26

Bug-fix release. Every fix below is verified against a live SAP S/4HANA system
(kernel 793, release 758) unless noted otherwise.

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

[Unreleased]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/randomstr1ng/saprfclib/releases/tag/v0.1.0
