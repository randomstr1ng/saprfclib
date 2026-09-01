# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Tests for the metadata bootstrap — `_call_bootstrap` and `_call_struct_bootstrap`,
  which run before any first call to a function module and were the largest untested
  block in the tree. The reason was structural rather than accidental: nearly every
  other test pre-populates the descriptor cache so `call()` skips the bootstrap, which
  left the path that runs in production against every unseen function module with no
  cover at all. Driven from the captured GFI replies rather than a stub, so the column
  layout, the EXID mapping and the compressed-table path are exercised as they arrive.
  Pins the two halves of the degradation contract: a DDIC layout that cannot be fetched
  warns and names both the type and the parameter, and the parameter it belongs to then
  refuses to encode rather than putting a well-formed meaningless record on the wire.
  `connection.py` 63% → 66%.

- `PoolMetrics`, on both `ConnectionPool` and `AsyncConnectionPool` as `.metrics`,
  plus `pool.stats()` folding in the live gauges (`in_use`, `idle`, `size`,
  `max_size`). Closes the half of #22 that connection-level metrics could not: was
  the caller even holding a connection yet? A high `mean_wait_s` with no `timeouts`
  says the pool is undersized, `timeouts` say badly undersized, and a high
  `discards` count says connections are dying between uses and that cost is being
  paid on every acquire.
  The accounting keeps the awkward cases honest. A connection that fails its health
  check is a `discard`, never a `hit` — crediting it would report a reuse nobody
  could use. A failed `open()` is not a `create`, since the reservation is undone
  and counting it would show a pool steadily opening connections that do not exist.
  `mean_wait_s` divides by acquires *plus* timeouts, because a caller that waited
  the full deadline and got nothing waited longest of all, and dropping it would
  make an exhausted pool look faster than a healthy one.

- `ConnectionMetrics.total_server_duration_s`, `mean_server_duration_s`,
  `server_timed_calls` and `server_time_fraction`. The fraction is the number the
  0x0667 work was for: near 1.0 means latency is the ABAP, near 0.0 means it is the
  network, the gateway or a queue. The mean divides by the calls that actually
  reported a server time, not by every call — folding an absent measurement in as
  zero would understate server time by whatever share of the traffic omits the tag,
  and would do so with a perfectly plausible-looking number. `server_timed_calls` is
  exposed so a 0.0 fraction can be told apart from "nothing was measured".

- `CallStats.server_duration_s` — the server's own duration for the call, taken from
  tag 0x0667 of the response. It is the one number that separates server time from
  network time: a call taking 3 s of wall clock is a different problem depending on
  whether the server spent 2.99 s of it or 40 ms. `None` when the response carries no
  such field, which is deliberately distinct from `0.0` — no release rule requiring
  the tag is established, so absence means unknown, and a fabricated zero would enter
  a latency series as an impossibly fast call.


- Tests for the codec's refusal branches — the module where a defect corrupts *data*
  rather than failing. A zero or truncated BCD field, an invalid sign or digit nibble, an
  out-of-range `INT1`, and a zero-row-size table are each refused rather than
  interpreted, because every one of them would otherwise hand the caller a plausible
  wrong number. `codec.py` 92% → 96%.
- Tests for the transport accessors and the async transport, including that the 128 MiB
  frame cap is enforced on the *declared* length before any payload is read — checking
  after reading is exactly what the cap exists to prevent. `transport.py` 80% → 94%.

- Tests for the wRFC message builders, including two security invariants asserted
  together: the password must **not** appear in the frame as plaintext (it is scrambled,
  as on the classic path) and must **still affect** the frame. Checking only the first
  would pass equally well if the password were dropped entirely, which would be the
  worse bug; checking only the second would pass if it travelled in clear.

- Tests for the client session's truncated-response guards — a short NI version, GW
  connect or GW done frame must be rejected rather than read past — and for the
  fixed-width client address field. `session.py` 85% → 89%.

- Tests for the server-session state machine, which was the lowest-covered module at
  60%: the post-registration frame builders, the NI framing guards on inbound gateway
  data (a frame whose declared length disagrees with what arrived must be rejected, not
  handed to the TLV walkers as if complete), and the registration-ACK handle extraction.
  `server_session.py` 60% → 90%.

- Tests for the pool's error and shutdown paths, which were entirely uncovered and are
  where a fault stays silent: a failed `open()` must return its reserved slot (otherwise
  the pool shrinks permanently and eventually deadlocks at `max_size`, reporting only a
  timeout long after the cause) and must wake any waiter; a connection released into a
  closed pool must be closed rather than returned to a dead idle set. `pool.py` 73% → 86%.
- Tests for the async server's accept loop: short and unknown frames must not stop it (a
  loop that exits on the first unexpected frame is trivially denial-of-serviced by one
  stray packet), and finished dispatch tasks must not accumulate.

- Tests for the server paths that had none: gateway service/port resolution, the
  dispatcher-name derivation, bounds safety in the inbound `0x5001` scanner, and the
  TID validation guards on inbound transactional frames. `server.py` coverage rose from
  55% to 62%; the coverage floor is raised to match.

- **Coverage is measured and gated.** CI now runs with `--cov` and a floor in
  `pyproject.toml`, so coverage cannot quietly fall — deleting tests or adding a large
  untested branch fails the build instead of passing silently. There was previously no
  measurement at all: 781 tests and no idea what they reached.
- Branch coverage is enabled, which is stricter than counting statements — the same
  suite reads 74% by statements and **72% by branches**. Almost all of that difference
  is error handling, reached only when something goes wrong, which is exactly where this
  project keeps finding bugs.

- **Per-connection call metrics (#22).** `Connection.metrics` and
  `AsyncConnection.metrics` expose a `ConnectionMetrics`: call count, failure count,
  total/mean/max latency, and wire bytes in and out. `as_dict()` returns a flat
  JSON-ready mapping for an exporter, and `metrics.last` holds a `CallStats` for the
  most recent call. Failures are counted **and timed** — a view that measures only
  successes hides the case where a system starts failing slowly, which is the trend
  worth alerting on.
- Latency is stored as a total plus a count rather than a list of samples. Keeping
  every sample would be a slow memory leak on a pooled connection that lives for weeks,
  and mean plus max is what a dashboard plots.
- `Transport` and `AsyncTransport` count cumulative wire bytes, including the 4-byte NI
  length prefix, so the figures match a packet capture rather than the payload the RFC
  layer sees.

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


- Tests for the wRFC (ngrfc V1) value encoders, which were almost entirely uncovered
  because the only tests reaching them were integration tests needing a live WebSocket
  endpoint — despite being pure byte-building. Covers the fixed-width contract for CHAR,
  INT and BCD (marker byte plus exactly the declared width, blank-padded and truncated),
  the BCD sign nibble, and refusal rather than wrapping when a value will not fit.

- **A crafted inbound frame could burn CPU quadratically on the RFC server.**
  `_extract_5001_params` advanced its scan position only when a parameter value was
  *found*, so a block of declarations with no matching values made every later name
  rescan the frame to the end. 800 declarations in a 269 KB frame cost **six seconds**
  of CPU, and this runs on every inbound frame a registered server receives — one small
  frame could saturate it. Now stops on the first failed search, which is also the
  correct answer rather than merely the fast one: a search that failed over a region
  fails identically for every later name, since it covers the same bytes. Same input:
  6.07s → 0.008s.

- **A program ID longer than 8 characters registered under a truncated name.** The NI
  init frame's program-ID field is 16 bytes, but the value was cut to 8 before padding —
  `SAPRFC_TEST` went out as `SAPRFC_T`. A gateway that cannot match the registered name
  to its SM59 destination simply never sends the server a call, and nothing anywhere
  reports a problem. Invisible in the capture it was written from, which used the
  seven-character ID `python3`: slicing at 8 changed nothing there, so a byte-exact
  golden test passed throughout.
- **A system number above 99 built a malformed connect frame.** `sapdp<NN>` is an
  eight-byte field, so `sysnr=100` produced `sapdp100` with no trailing space and grew
  the frame by a byte; it also computed gateway port 3400, which is not a gateway. The
  value is now validated where it is used and at `connect()`, before a socket is opened.


- `tests/test_fixed_width_fields.py`, covering the whole defect class rather than the
  individual instances. Four bugs of this exact shape were found in one session, from
  two mechanisms: assigning to a fixed `bytearray` slice, where a wrong length silently
  **resizes** the buffer instead of raising; and `.ljust(n)`, which sets a **minimum**
  width, not a fixed one. Both are invisible whenever the captured value happened to be
  the right length — which is why each survived a byte-exact golden test. The tests pin
  the language behaviour itself alongside the specific fields, and an AST scan of every
  fixed-width slice assignment in `src/` now backs the review.

- **A malformed `local_ip` changed the length of the first frame of every connection.**
  The NI version request carries the client address in a fixed 4-byte field. The
  existing guard could not fire for a value with the wrong number of octets —
  `bytes(...)` succeeds on `"1.2.3"` — and assigning three bytes to a four-byte slice
  *shrinks* the `bytearray`, producing a 63-byte request instead of 64 (65 for a
  five-octet value). Now built through a helper that always returns exactly four bytes,
  falling back to loopback for anything unusable, since the field is informational and
  should not stop a connection.

- **An over-long gateway host corrupted the post-registration frame, silently.**
  `ServerSession.build_post_reg_a` writes a caller-supplied host into a fixed 224-byte
  frame with no bound. Between 129 and 144 characters the padding slice went empty and
  the host overran the trailing zero region, leaving a 224-byte frame with wrong
  content; past that, assigning to a `bytearray` slice **grows** it rather than raising,
  so a 200-character host produced a 280-byte frame — a length the gateway cannot parse.
  The field is now bounded at its actual width (128 bytes) and a non-ASCII host is
  refused with a message that says why, rather than a bare `UnicodeEncodeError`.

- **The async RFC server leaked one `asyncio.Task` per call served.** `_handle_client`
  appended every dispatch task to a list and never removed it, so a connection handling
  a million calls retained a million finished tasks. Nothing failed visibly — it is a
  leak proportional to work done, the kind that only appears after long uptime. Now a
  set with a done-callback, which also keeps the strong reference asyncio requires:
  the loop holds only a weak reference to a running task, so without one a dispatch can
  be garbage-collected mid-flight.

- **The gateway service name could resolve to the wrong port, silently.** `_gwserv_port`
  answered `sapgwfoo`, a bare `sapgw`, and anything else it could not parse with **3300**,
  computed `sapgw999` as **4299** and `sapgw-5` as **3295** — ports that are not gateways
  at all. A server that registers against the wrong gateway reports no error; it simply
  never receives the calls it is waiting for, which looks like the caller's problem. Each
  unreadable form now raises, and the instance is range-checked against the documented
  `sapgw<NN>` = `33<NN>`, 3300–3399.
- `_dispatcher_svc_8` mishandled the SNC gateway. It computed the instance as
  `port - 3300` unconditionally, so the documented SNC gateway port 4800 became instance
  1500 and produced `sapdp150` — a truncated name for a dispatcher that does not exist.
  Both documented ranges (`33<NN>` and `48<NN>`) now map correctly, and a port in neither
  raises instead of guessing.

- Corrected the recorded meaning of TLV tag `0x0667`. `docs/protocol/framing.md` gave it
  as "server call duration, float64 LE, microseconds" at **capture** tier, but a capture
  shows bytes (`138.0`), not what they count. The two golden fixtures disagree with each
  other — one reads it as microseconds, the other as `[ASSUMED]` "timeout in seconds" —
  and three readings fit both observed values: microseconds, milliseconds, or not a
  duration at all. The tag is now labelled `[ASSUMED]` with what would settle it. The
  new metrics deliberately time calls with a local clock instead: a latency number
  quietly wrong by three orders of magnitude is worse than no latency number.

- **SAProuter hop passwords (`/P/`) are implemented.** A route entry is three
  NUL-terminated fields — host, service, password — and an entry without a password
  still ends with the empty password's NUL. Confirmed by capturing `niping` sending a
  password-protected route; `build_ni_route` now reproduces that frame and the
  unprotected one byte for byte. `/P/` was previously parsed and then discarded.
- **The route-entry layout was wrong, and correct only by coincidence.** The service
  was padded into a fixed 6-byte NUL-filled field, which for a four-character port is
  byte-identical to the real form (`"3299" + NUL + NUL` equals `"3299\0"` followed by
  the empty password's `"\0"`). Every numeric port therefore produced a valid frame and
  the mistake stayed invisible — including to a byte-exact golden test. It would have
  surfaced the moment anyone used a service *name*: `sapgw00` is seven characters,
  truncated to `sapgw0`, malforming the frame.

- **`connect(saprouter=...)` could not work, and now does.** A SAProuter answers an
  accepted `NI_ROUTE` with `NI_PONG\0` before it starts forwarding. That frame was
  never read, so it sat at the head of the stream and the handshake's first read
  returned it instead of the NI version response — putting every subsequent frame one
  position out of step. Confirmed against a live SAProuter 40.4, where the full
  handshake now completes through the route.
- A refused route reports the router's own message. `NI_RTERR` carries a NUL-separated
  `*ERR*` record — the same shape the gateway uses — naming the source address, target
  and port, as in `saprouter: route permission denied (203.0.113.42 to 10.99.99.99,
  3300)`. That is reported verbatim instead of a generic explanation, because it is
  what someone debugging a denied route needs.
- An unexpected answer to `NI_ROUTE` now stops the connection rather than being fed to
  the handshake as if it were data.

- **A SAProuter refusal is now reported instead of being misparsed.** After sending
  `NI_ROUTE` the router's answer was never inspected, so an `NI_RTERR` — the router
  declining to carry the route, whether from its permission table, a bad hop password
  or an unreachable target — reached the session as though it were the frame the
  handshake was waiting for. The rejection then surfaced several steps later as a
  confusing protocol error. NI control messages are the NI layer's business, so the
  check lives in the transport and covers every inbound frame on both the sync and
  async paths.
- **A route password is refused rather than silently dropped.** `/P/` was parsed into
  `RouteHop.password` and then never transmitted, so a password-protected route was
  sent without its password and the router simply refused it — leaving the caller a
  rejection they had no way to connect to the password they supplied. Where the
  password sits in the `NI_ROUTE` frame has never been captured, so `build_ni_route`
  now raises `NotImplementedError` naming the gap.
- Removed a stale `[ASSUMED]` label on the `NI_ROUTE` payload layout. It predated the
  2026-06-27 capture and contradicted `build_ni_route`'s own docstring and its
  byte-exact golden fixture.

- **The SAPMS binary protocol works.** Captured from SAP GUI performing a group logon,
  then reproduced against the live message server by this library, which answered
  `errorno 0` and returned the real server list. `MessageServerClient.resolve_full`
  now runs the actual exchange — attach (operation `0x08`), request (operation `0x01`,
  selector `0x1d`), detach (`0x04`) — and parses the reply. Golden fixtures for all
  five frames are in `tests/golden/router/`.
- There are **two server-list opcodes with different payload formats**, both genuine:
  `0x1e` (version 1) carries newline-separated `KEY=VALUE` text such as
  `ASNAME=…|HOSTNAME=…|PORT=3200|SAPSRV=…|SNC=…`, while `0x05` (version 4) carries a
  binary fixed-width entry table. The header is identical in both. `parse_ms_list_reply`
  handles the text form and `parse_sapms_server_list` the binary one, dispatched on the
  opcode rather than assumed — and meeting the other form names the parser that handles
  it. The binary parser was very nearly deleted as dead code on the strength of one
  capture that happened to use the other opcode.
- `PORT` in that reply is the **dispatcher** port (`32<NN>`), not the gateway — the
  captured record reads `PORT=3200` for a server whose gateway is 3300 — so the system
  number derives from the dispatcher formula and the caller adds 3300 (or 4800 for SNC).


- `CLAUDE.md` gains **"Nothing ships unvalidated — including defaults"**. The evidence
  tiers governed wire values; this governs commits, and names the things that do not
  look like protocol facts but are: default values, fallback paths, and anything
  learned from reverse engineering. RE establishes what to *test*; the wire establishes
  what is true.

- **Load-balanced logon could not work, and failed silently.** `connect(mshost=...)`
  derived the message-server port as a hardcoded 3600 — the function took a `sysid`
  argument and ignored it, while its docstring claimed "3600 + sysnr". Both are wrong:
  the port is `36<nn>` where `nn` is the **message server's own instance number**, which
  is not the application server's system number and cannot be inferred from it. On A4H
  the app server is sysnr 00 while the message server is instance 01, so it listens on
  3601 and **3600 refuses connections outright**. Added `msserv`, accepting a port or a
  service name resolved through `/etc/services` as the SAP tools do; an unknown service
  name raises rather than defaulting, since defaulting means silently connecting
  somewhere else.
- Group logon now resolves over the message server's **HTTP interface**, which is
  line-oriented, documented, and confirmed against a live server (golden fixtures in
  `tests/golden/router/`). The binary `**MESSAGE**` protocol in `router.py` carries most
  of this project's `[ASSUMED]` labels and, tested live on 2026-08-31, does not work at
  all: the server accepts the connection on 3601 and then answers nothing — no
  acknowledgement, no list, no error. Letting an unverified path choose which
  application server a caller talks to is not a failure the caller can see, so it is no
  longer the default. `ms_use_http=False` still selects it for anyone working on it, and
  `docs/protocol/message_server.md` records what a capture would need to close the gap.

- **Connections no longer wait forever.** `connect_tcp` was called with `timeout=None`
  by default, so a wedged SAP work process blocked the caller indefinitely with no
  recovery. `connect_timeout` now defaults to 10 seconds.
- **Connect and read timeouts are separate settings.** `socket.create_connection` leaves
  its connect timeout on the socket, where it silently becomes the per-read timeout — so
  being strict about connecting (`timeout=5`) also aborted any RFC call running longer
  than five seconds. `connect()` and `connect_async()` now take `connect_timeout`, and
  `connect()` also takes `read_timeout` (default `None`: RFC puts no bound on how long a
  call may legitimately take). The single `timeout` argument still works and still
  applies to both.
- **TCP keepalive is enabled on every connection.** A stateful firewall or NAT between
  client and SAP silently drops an idle mapping and tells neither end; without keepalive
  the next read blocked until the OS default gave up, two hours on Linux. Probing now
  starts after 60s idle and gives up after 5 probes at 10s, detecting a dead path in
  about 110 seconds. The pool's health check could never cover this: it runs at acquire
  time, and this is a connection that was healthy when it was lent out.
- **A pool now shares one metadata cache.** Each connection built its own, so a pool of N
  connections calling M function modules paid N×M `RFC_GET_FUNCTION_INTERFACE`
  round-trips to learn the same M answers — 1000 avoidable calls for a 20-connection pool
  and 50 function modules. A descriptor describes the system, not the socket it arrived
  on. `MetadataCache` is now thread-safe, and `connect()`/`connect_async()` accept
  `metadata_cache` so callers can share one explicitly. The lock is deliberately not held
  across the fetch: that would serialise every first call in the pool behind one
  connection, a worse trade than a rare duplicate fetch.

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
- The SQLite stores close their connection when the open is refused. `__init__` opens
  the database before validating its schema, so a rejected open left the half-built
  object unreachable with a live handle, finalised at an arbitrary later point — the
  resulting `ResourceWarning` lands on whichever unrelated test or code path is running
  then.
- The SQLite stores refuse a database written by a newer `saprfclib` instead of reading
  and writing it through the older schema they know — on a store whose purpose is
  surviving a crash intact. They also stamp `PRAGMA user_version` from `_SCHEMA_VERSION`
  rather than a repeated literal `1`; the two were independent, so bumping the constant
  would have created a new schema and recorded it as the old version.
- The server logs, at DEBUG, an output parameter its handler did not supply. Skipping it
  is correct — outputs are optional — but the client simply saw the key missing.
- `examples/09_bapi_user_create.py` no longer reports a failed commit as success. The
  check inspected `RETURN` only as a structure, so on a system whose
  `BAPI_TRANSACTION_COMMIT` answers with a table, an error row fell through it and the
  script printed that a user had been created when it had not. Both shapes are handled,
  and a shape it does not recognise raises rather than being read as success.

- DECFLOAT16 parameters no longer disappear from a function interface.
  `RFC_GET_FUNCTION_INTERFACE` reports them with `EXID = 'a'`, which was absent from
  the EXID table, so every such row failed to parse and was dropped — a function
  module with seven DECFLOAT16 parameters came back describing only its three
  DECFLOAT34 ones, and the call then went out missing seven arguments instead of
  failing. Confirmed by live capture on A4H (kernel 793). The previously mapped `v`
  has never been observed and is now labelled `[ASSUMED]`. The wire encoding itself
  is still unconfirmed, so `encode`/`decode` continue to raise: the failure moves
  from "parameters silently missing" to "this type is not implemented".

- **DECFLOAT16 and DECFLOAT34 are implemented (#13).** The wire form is IEEE 754-2008
  densely packed decimal, **little-endian** — settled by live capture from A4H
  (kernel 793) of a purpose-built remote-enabled function module returning nine values
  of known decimal magnitude at both widths. All nine decode correctly and re-encode
  byte-for-byte; `tests/golden/serialization/decfloat_response.bin` is the fixture and
  every expectation in `tests/test_decfloat.py` is driven from it. `encode`/`decode` no
  longer raise for these types, and values are `decimal.Decimal` throughout.
- The documented byte order for DECFLOAT was wrong. `docs/protocol/serialization.md`
  recorded big-endian as "the neutral network byte order", taken from SDK header
  commentary rather than the wire; the capture disproves it. This mattered more than a
  normal byte-order error: read big-endian, `42.0` decodes to `4.00000000801022E-128` —
  a well-formed number rather than an error, so a wrong assumption here would have
  returned a different value silently, in the one type that exists to carry money
  exactly.
- DECFLOAT encoding refuses rather than rounds. More significant digits than the width
  holds, or an out-of-range exponent, raises `ValueError`; truncating to fit is the
  corruption this type exists to prevent.

### Fixed

- The wRFC "E=163" error was fabricated by this library, and is gone. Three code paths
  produced it and none read it from the wire: two raised the hardcoded string
  `"163: Error when receiving data for an RFC."`, and the third used `163` as a
  *fallback for when the server reported no return code at all* — inventing a specific
  failure number to describe a reply that carried none. A probe against A4H kernel 793
  shows the wRFC LOGON succeeding with a 1118-byte reply in under 100 ms, so the
  premise of issue #14 ("`RFC_GET_FUNCTION_INTERFACE` returns exception 163") was our
  own message read back. Each site now reports what actually happened — the WebSocket
  close code and reason, or that no rows, no return code and no message came back.
  Seven comments asserting the disproven story are corrected, an integration test that
  required `"163"` in the message no longer pins the fiction, and
  `_ws_e163_classic_fallback` is renamed. The gap itself is real and still open; the
  number never was.

- Disabling wRFC TLS verification now writes a log record as well as raising a warning.
  The two channels fail differently: a warning is shown once per call site and vanishes
  under `python -W ignore` or a broad `filterwarnings()`, both of which a long-running
  service is likely to have set for unrelated reasons. The log record survives that, so
  the process where it matters most still leaves a trace that its RFC traffic was
  unauthenticated. The defaults themselves were already correct — `connect`,
  `connect_ws` and `_make_ssl_context` all verify unless told otherwise — and are now
  asserted rather than assumed, along with the resulting context actually being
  `CERT_REQUIRED` with hostname checking and a TLS 1.2 floor.

- Message variables V2–V4 are confirmed at `0x0412`–`0x0414`, following V1 at `0x0411`.
  Previously inferred from `0x0411` alone, because no capture carried more than one
  variable. A purpose-built RFM raising `MESSAGE e398(00)` with four **distinct** values
  put each in its own tag — four copies of one string would have parsed identically with
  the tags in any order.
- The free-text tag `0x040B` is removed. It had never appeared in any capture and was
  nonetheless tried *first* when resolving an exception's message, ahead of `0x0402`
  which is captured and confirmed on kernel 752. The same probe aimed at it directly: a
  reply carrying a genuine four-variable message is exactly what would populate a
  free-text tag, and it is absent. One untested guess outranking one confirmed fact is
  the wrong way round.
- `AbapApplicationError`'s diagnostic string now carries the message class, number and
  variables when the server sends no assembled text. Kernel 793 sends none for a classic
  exception — `0x0402` is absent too, and the sentence is the client's to build from
  `T100`, which this library does not do. The error reported a bare `FOUR_VARIABLES`
  while holding `ALPHA1`, `BRAVO2`, `CHARLIE3` and `DELTA4` unread on the object. On this
  kernel that was the common case, not an edge case. A server-supplied message still
  wins, so the 752 shape is unchanged.

- The multi-frame continuation markers are settled by a 22-frame capture. Bytes 17–20
  (BE int32) read `-1` on a continuing frame and `500` on the last; bytes 60–63 (BE
  uint32) read `0` and `1`. All twenty-one continuing frames of a 591337-byte reply
  agreed. A two-frame capture could not have shown this — with two frames "continues
  the response" and "does not end the stream" are the same statement.
  They remain **not** the reassembly condition, which has not changed: both read the
  continuing value on two complete terminal replies (a refused logon, an incomplete
  signon), so a loop keyed on them would wait forever on a failed logon. The `0xFFFF`
  terminator still drives reassembly. The marker is now used in the one direction it is
  safe in — a frame that reports itself final while the stream is still short is
  refused, because reading on would consume the next call's reply.
- Recorded that the gateway chunks at exactly 28000 payload bytes per frame, which is
  why a `DD03L` read crosses into several frames at around 2000 rows.

- A connection whose negotiated codepage is not the `4103` Unicode wire mode is now
  refused at handshake, naming the codepage it got and the one it needs. Non-Unicode
  systems are out of scope — SAP ended support for them with NetWeaver 7.5 — but that
  alone would not justify a hard refusal. The reason it does is that `unicode_mode` is
  *derived* as "the wire is UTF-16LE" and *spent* by the codec as a byte-order
  selector: `_uc_encoding` returns `utf-16-be` whenever it is false. On a genuinely
  non-Unicode connection that does not fail — it decodes single-byte text as UTF-16BE
  and returns mojibake in every character field, on a connection that looks healthy
  throughout. The refusal is scoped to live connections, so offline descriptors built
  without a negotiated codepage keep working.

- Two stale claims removed. `router.py` said the binary message-server protocol was
  unconfirmed and that the server "accepts the connection and then answers nothing" —
  written before the operation byte at 0x43 was corrected to `0x08`, and contradicted
  by four live-reply fixtures in the same tree. `connection.py`'s `connect()` docstring
  said the SAProuter and message-server wire bytes were unverified, after both had been
  verified byte-exact. A stale uncertainty label is worse than none: it reads as current
  fact and steers a reader away from a path that works.
- Uncertainty labels audited: 14 sites down to 9, all nine now real open questions with
  a stated way to settle them. Three of the removed were never assumptions at all —
  comments that mentioned the label to say it had been resolved, or that there was none
  here. The token has to stay searchable, and meta-mentions bury the real ones.
- The server-list entry layout is described from what the capture shows rather than
  from a guess. Bytes 80–124 hold a space-padded **service name** (`tick-port` on the
  one entry with a real port, `-` on the two placeholders), not the "secondary name /
  padding" recorded before. Byte 147 reads `0x01` on the real application server and
  `0x05` on the placeholders — recorded as a correlation from three entries in one
  capture, which is not an enumeration.

- Responses larger than one gateway frame are now reassembled instead of failing.
  `RFC_READ_TABLE` on `DD03L` past ~2000 rows returned a 28080-byte frame cut inside a
  250-byte `0x0305` record plus a 25593-byte continuation, and `Connection.call` read
  only the first. The bodies concatenate directly — no trailer, no preamble, no
  re-framing. Reassembly is driven by the stream's own `0xFFFF` terminator and
  deliberately **not** by either header field that looks like a "more follows" marker:
  bytes 17–20 and 60–63 are the same signal, and both also fire on complete terminal
  replies (a refused logon, an incomplete signon), so a loop trusting either would hang
  on a failed logon waiting for a frame that never comes. Fixtures
  `multiframe_read_table_part1.bin` / `_part2.bin`.
- Bytes 56–59 of the GW header are the frame's own payload length (BE uint32), exact on
  all 16 frames checked — the 2 above plus 9 independently captured golden fixtures.
  The previous mapping of 52–63 as an RFC library name string is disproven; the region
  is three BE uint32.

- Tag 0x0667 is settled: it is the server-side duration of the answered call, in
  microseconds, per call and not cumulative. The two golden fixtures had contradicted
  each other (one read it as microseconds, the other as an `[ASSUMED]` timeout in
  seconds) and neither could be right from a capture alone, which shows `138.0`
  without saying what 138.0 counts. A first probe varied rows read, saw the value move
  400x, and concluded "it tracks the work, so it is a duration" — which does not
  follow, because rows read moves server time and response size together and a byte
  counter fit the numbers equally well. `RFC_PING_AND_WAIT` separates them: it sleeps a
  known interval and returns a constant-size reply. Across 0/1/3-second sleeps the
  response held at 236 bytes while the value tracked the sleep to 0.1% read as
  microseconds, each reading bracketed by the sleep below it and the wall clock above,
  and the third call read its own duration rather than a running total. The `[ASSUMED]`
  labels are removed and the timeout reading is recorded as disproven.

- A connection whose reply could not be read to its end is now retired instead of
  returned to the pool. Previously the session went back to `READY` with the unread
  remainder still queued on the socket, so the *next* call read the previous reply's
  leftovers and returned a result belonging to different arguments — a silent
  mismatch set up by a failure that had already been reported. `BROKEN` is terminal
  (there is no record boundary to resynchronise to), every later operation refuses
  and names the original fault, and the pool discards such a connection without
  probing a stream it already knows is unreadable. ABAP application errors and
  system failures are excluded: those frames parsed correctly, so the connection
  stays usable rather than forcing a reconnect on every short dump.


- **An over-long function name built a malformed wRFC frame.** The call-name fields pad
  to a fixed width with `=` and append `FT`. An over-long name does not truncate — the
  pad count goes negative and `"=" * -1` is the empty string — so the field came out
  *too long*: a 31-character name produced a 33-character call-begin field where the
  format requires 32, with nothing raising. ABAP caps function module names at 30, so
  such a name is invalid regardless, but building a malformed frame is the wrong way to
  report that.

### Corrected

Three claims committed earlier today were wrong, each in a way that read as a finding:

- **"The byte at `0x43` must be 3."** It is the *operation* byte and 3 is not one of
  its values. That came from a sweep of 0, 1, 2 and 4 that never tried 8 — the value a
  real client sends — and every candidate in it was paired with a `msgtype` the server
  would not accept regardless, so the sweep measured nothing at all.
- **"Return code −20 means the server's ACL refused the attach."** No ACL is configured
  on the test system. −20 was the server rejecting an invalid operation byte.
  Attributing it to `ms/acl_info` was a guess phrased as a diagnosis.
- **The original `msg_type=0x02` / `direction=0x08` at `0x42`/`0x43` were correct** and
  were replaced with a wrong constant taken from a legacy code path. The real defects
  were the frame length (114 against the correct 110 — enough on its own for the server
  to close the connection without replying) and the name-field layout.

- Message-server and gateway ports are now sourced from SAP's *TCP/IP Ports of All SAP
  Products*, not from observation alone. The documentation corrected an incomplete
  conclusion: the `36<NN>` message-server formula applies **only** to systems installed
  before SAP NetWeaver 7.0 with a central instance. On an SCS/ASCS layout — every modern
  install — the port is `rdisp/msserv`, anywhere in 0–65535, with a documented default
  of **9310**. There is no formula to apply, which is a stronger reason for having no
  default than the one previously recorded. Each plausible constant is wrong for a
  different layout: 3600 for a legacy central instance, 9310 for a default SCS, 3601 on
  the system used for testing.
- The gateway derivation `(4800 if snc else 3300) + sysnr` is confirmed twice over:
  documented as `sapgw<NN>` = `33<NN>` and `sapgw<NN>s` = `48<NN>`, and independently
  reported as `RFC 3300` / `RFCS 4800` by the message server's own service list. Note
  `<NN>` there is the application server's instance number, unlike the message server's.
- Reading `sapms<SID>` from `/etc/services` is confirmed as the intended client-side
  mechanism rather than a convenience: the same table states "You can reassign service
  names to an arbitrary value after installation in /etc/services".
- The message-server HTTP interface is documented as `81<NN>` and **"Not active by
  default"**, which is why its absence is reported as a configuration fact rather than
  an error.

- **The binary message-server frame layout is now confirmed, and it was wrong.**
  Validated against a live A4H message server by sending candidate frames and
  recording which drew a reply, which drew a specific error, and which were dropped.
  The attach frame is **110 bytes**, not the 114 the builder produced — the server
  closes the connection on the old frame without replying at all. `0x0e` is the start
  of a 40-byte `toname`, not a one-byte "sender type", and `0x44` holds the 40-byte
  `fromname`, not a 10-byte "opcode name". Both fields are space-padded, which is why
  the mistake survived beside a partial capture: the bytes looked plausible.
- Two constants are now evidenced rather than assumed: version `4` at `0x0c` (sending
  5 is answered with −12 *"invalid client version"*, which is what proves the field's
  meaning) and the byte at `0x43`, which must be `3` — 0, 1, 2 and 4 each get the
  connection dropped.
- Message-server return codes are decoded, from a **signed** byte at `0x0d`. Read
  unsigned, `0xec` is 236 rather than −20, turning *"access denied"* into a number.
- `MessageServerClient.resolve` no longer runs an invented protocol. It sent a 2-byte
  length-prefixed group name — a shape created to satisfy `MockTransport` and
  uninterpretable by any message server. Its test passed because the stub and the test
  agreed on a protocol that does not exist. It now delegates to the real SAPMS
  exchange, and reports the server's own return code instead of waiting.
- Both message-server builders carried their own NI length prefix while handing the
  result to a transport seam that adds one, and read the reply magic at offset 4 of a
  payload whose prefix had already been stripped. The two errors cancelled out under
  `MockTransport` and could not have worked on a socket.
- **No numeric default for the message-server port.** The previous commit replaced a
  hardcoded 3600 with 3601, which is the same mistake with a different number: 3600 is
  right for a single-instance system and 3601 for an ASCS split, and nothing observable
  from the client distinguishes them. The instance number now comes from the
  `sapms<SID>` entry in `/etc/services`, and when that is absent the caller is asked for
  `msserv` rather than sent somewhere plausible.

### Documentation

- Corrected the worked DECFLOAT16 example in `docs/protocol/serialization.md`. It read
  `22 38 00 00 00 00 04 20` for 42.0; under a standard DPD reading those bytes are
  `1020` — the exponent field said 0 rather than −1, and the declet `0x420` spells the
  digits 2‑2‑0 rather than 4‑2‑0. The example was labelled `[ASSUMED]` and no code
  depends on it, but a wrong worked example is what someone implementing the codec
  would check their work against. Also records that twelve is `…00 12` under DPD and
  `…00 0c` under BID, which makes a single captured value decisive between the two.
- Recorded what the 2026-06-26 DECFLOAT probe actually established: that three *guessed*
  function-module names do not exist, which is not the same as no such function module
  existing. Notes the dictionary tables (`DD04L`, `DD03L`, `FUPARAREF`, `TFDIR`) that
  answer the question directly.

- `CONTRIBUTING.md` gains a **Branch Model** section: never squash-merge `development`
  into `main`. A squash writes a commit with no ancestry link to what it flattened, so
  the next release PR re-proposes those changes and conflicts against work `main`
  already contains — a loop that recurs every release and compounds. Documents both
  remedies (merge commits for release PRs, or resetting `development` after a squash)
  and the preconditions for each.
- `docs/protocol/framing.md` now tabulates the two remaining `[ASSUMED]` exception tags
  (`0x0412`–`0x0414` for message variables V2–V4, and `0x040B`) with what would confirm
  each. `0x040B` has never been observed and is now known to be redundant with the
  confirmed `0x0402`; it is kept only because removing an untested fallback is no
  better evidenced than keeping it.


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
