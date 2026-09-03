# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- DECFLOAT works over wRFC (#19). That issue asked for `DECF16`/`DECF34` support in the
  wRFC ngrfc Q-markers; those Q-markers no longer exist, because the wRFC invoke turned
  out to be a classic invoke TLV stream and the same codec now carries these types on
  both transports. Verified by calling one function module over classic TCP and over
  WebSocket and comparing all nine returned values — identical, in both directions. The
  gap closed by the encoder becoming unnecessary rather than by being written.

- The empty-descriptor warning no longer fires on parameterless functions. It keyed on
  the row count alone, so `RFC_PING` — which has no parameters — produced "the descriptor
  will be empty and calls will reject all arguments" after a fetch that had worked
  perfectly. A warning that fires on correct behaviour trains its reader to ignore it,
  which costs the one time it matters. It now also checks whether the reply reported
  success (`0x0503`/`0x0420`, and `0x0417` for an exception), which separates "this
  function takes no arguments" from "we could not read the answer".

- A parameterless function could not be called over wRFC. The bootstrap raised
  `AbapSystemFailure` whenever the metadata reply held no parameter rows — but `RFC_PING`
  has no parameters, so its interface legitimately has none, and the error reported
  something that had not happened ("returned no parameter rows, no return code and no
  message" on a reply that had succeeded). Whether the fetch failed is answered by the
  reply itself: `0x0417` marks an exception, `0x0420` carries the return code. Those are
  consulted now; a row count of zero is not evidence.
- Every response read reassembles multi-frame replies, not just the classic invoke where
  reassembly landed first. The wRFC path reproduced the original truncation bug exactly —
  `RFC_READ_TABLE` on `DD03L` past ~2000 rows failing with `tag 0x0305 length 250 exceeds
  remaining payload` — while the classic path beside it had been fixed. Metadata fetches,
  structure lookups, LOGON replies, pings and bgRFC state reads all read replies that can
  exceed one frame; a 44-parameter interface already fills 2342 bytes. Only the NI/GW
  handshake loop still reads single frames, and it exchanges control frames rather than
  TLV result streams.

- Removed the ngrfc/Q-marker subsystem — 17 functions and about 700 lines — now that the
  wRFC invoke is a classic invoke TLV stream. It was unreachable from production and kept
  alive only by its own tests, which is the worst state for code encoding a *disproven*
  protocol shape: anyone looking for "the wRFC invoke builder" would have found
  `_build_ws_invoke_message` and reached for the wrong thing. Gone with it: the `0x5001`
  header constants, the ngrfc type map, and the `0x0136` session key and its counter,
  which belonged to a frame the server rejects.
  The tests went with their subject rather than being retargeted — 13 in
  `test_wrfc_encoding.py`, all of `test_wrfc_invoke.py`, and a 28-test section of
  `test_connection.py`. Tests for the still-live LOGON builder are kept, and the one
  guarding the session-token/invoke-key conflation now asserts that machinery stays
  deleted. Coverage floor raised to 78.5.

- `ping()` and `get_connection_attributes()` no longer refuse a fresh wRFC connection.
  `connect()` does the HTTP upgrade and defers the LOGON to the first call, so the
  session sat in `WS_PENDING` and both raised `operation not allowed in state
  'WS_PENDING'` — a description of the library's own bookkeeping that gave the caller
  nothing to act on. Both now complete the deferred LOGON, which on wRFC costs no extra
  round trip: the LOGON names `RFCPING` in its `0x0102` and the server runs it, so
  establishing the session *is* the liveness check.

- `ConnectionMetrics` recorded nothing on the wRFC and SNC paths. Call stats were
  collected only in `AsyncConnection.call`, which classic TCP delegates to; the other two
  transports run `Connection.call` directly, so metrics on either reported zero calls
  however many were made. A counter that is quietly absent is worse than one obviously
  missing — a dashboard showing nothing reads as an idle connection rather than a broken
  metric. Found when a live wRFC call succeeded and the run still printed `0 call(s)`.
  Failures are recorded on that path too, and `server_duration_s` now comes through.

- The wRFC invoke is verified against a call that actually completed. Fixtures
  `wrfc_invoke_request.bin` / `wrfc_invoke_response.bin` are a reference client's
  `STFC_CONNECTION` exchange, and `build_invoke_request` produces the request **byte for
  byte** — 648 bytes — while `parse_invoke_response` reads the reply unmodified and
  returns `ECHOTEXT='probe'`. Neither direction needed a wRFC-specific codec.

- **The wRFC invoke frame is a classic invoke TLV stream (#14).** There is no
  wRFC-specific invoke format — a reference client's invoke over WebSocket is
  byte-for-byte what `build_invoke_request` already produced for classic RFC, so the fix
  is a deletion rather than a new encoder. What it replaced sent **none of the
  parameters**: they went into a `0x5001` "ngrfc" body with Q-markers that the server
  never reads, alongside a `0x0136` session key it never issued and `0x0503`/`0x0420`,
  which are response markers appearing in a request. A call could not have worked even
  had the frame been accepted. Responses parse with the classic parser too, confirmed
  against reference captures of a metadata reply, a logon reply and a UCON rejection.
  Note the invoke is UTF-16LE while the LOGON is single-byte; that asymmetry is real, as
  the LOGON is exchanged in codepage 1100 and the session moves to 4103 after it.

- **The wRFC LOGON is confirmed working end to end (#14).** Instrumenting the wire shows
  the sequence: our 220-byte LOGON out, a 632-byte reply back with no embedded failure and
  return code zero, matching the size a reference client's accepted frame draws. Fixture
  `wrfc_logon_accepted.bin`, the counterpart to `wrfc_logon_receive_error.bin` — same
  system, same client, frame rebuilt.
  The LOGON also *runs* the function named in its own `0x0102`: the reply carries a
  complete RFC result rather than an authentication acknowledgement, so for a
  parameterless function the LOGON is the whole call.

- The wRFC LOGON no longer sends a random `0x0514` session token. A reference client's
  value is not random — across two runs minutes apart the first 9 of its 16 bytes were
  identical, a host-derived prefix followed by a counter — so filling the field with
  `os.urandom(16)` put a value there that no server has been observed to accept, and the
  symptom matched: the server stopped answering rather than objecting. The record is
  omitted instead, which is confirmed accepted, and the reply then omits it too. Sending
  nothing is better evidenced than sending a guess, and reverse-engineering how the
  reference derives the value would only produce another thing to validate.

- The wRFC LOGON sent a two-byte language code where the wire carries one. `connect()`
  accepts a two-character ISO code and the builder used `lang.upper()`, so `"EN"` went
  out as two bytes, the frame came to 240 against a working 238, and the server rejected
  the logon without indicating which field was wrong. The classic logon path already
  normalised this through `_encode_logon_language`; only the wRFC builder did not — a
  helper in the same module is no protection if the new code does not call it. The frame
  now matches a reference capture field for field, with only the session token and
  password seed differing, as those are random per connection.
- `_build_ws_logon_message` no longer accepts `server_host`, `server_port`, `sysnr` or
  `local_port`, none of which appear in an accepted frame. They survived the rewrite
  because both call sites splatted the stored auth dict wholesale, which is exactly how a
  parameter comes to be accepted and ignored; the call sites now pass their arguments
  explicitly.

- `connect(read_timeout=...)` now reaches the WebSocket transport. It was accepted and
  silently dropped on that path: the value went to `socket.create_connection` as the
  *connect* budget and nothing applied it afterwards, so a caller who asked for a bounded
  read got an unbounded one. A server that stopped answering then blocked them forever
  with no way to tell a slow reply from a dead connection. The default stays `None`,
  matching the classic transport — an RFC call may legitimately run for hours, so the fix
  is that a caller *can* bound it, not that one is imposed.

- **The wRFC LOGON frame is rebuilt to a shape the server accepts (#14).** Replaying a
  reference client's LOGON from this library's own transport was accepted, which
  localised the entire fault to the frame — the HTTP upgrade, the WebSocket layer and the
  TLS were never at issue. Substituting one field at a time into that accepted frame then
  showed which records the server inspects: the program name `0x0130` and function name
  `0x0102` are free, `0x0514` is optional (omitting it is accepted and the reply omits it
  too, so the client proposes the token rather than the server issuing it), and `0x0117`
  is not — a wrongly encoded password is answered "Name or password is incorrect".
  Three things were wrong:
  - **A `0x5001` ngrfc record was sent and should not exist.** It tells the server to
    receive RFC data for the call; there is none, so it answered
    `CALL_FUNCTION_RECEIVE_ERROR` — which is that sentence read literally. Both values
    previously tried in that record failed for the same reason. Removing it alone is
    necessary and not sufficient: on its own it produces silence rather than an error.
  - **Every string was UTF-16LE.** A wRFC request is single-byte; only the response is
    UTF-16LE. This is most of why the frame was ~1040 bytes against a working 238.
  - **Twenty-three records were sent that a working client does not**, including
    `0x0420`, `0x0503` and `0x0512` — response markers appearing in a request.
- The wRFC password field `0x0117` is single-byte, not UTF-16LE. An accepted frame's is
  17 bytes for a 13-character password: a 4-byte seed and a 13-byte body. Thirteen is
  odd, so the body cannot be UTF-16 at all. `latin-1` is used so a password that cannot
  be represented raises rather than substituting a character and authenticating as
  something else.

- Documented what a working wRFC LOGON frame contains (#14). A reference SDK client
  opens a session against A4H that this library cannot, and its frame is 238 bytes to our
  ~1040. Three differences, none of them the credentials:
  - **There is no `0x5001` ngrfc record.** The function is named in `0x0102` and the
    record set ends. We wrap a `0x5001` record around a body the server then tries to
    read RFC data from, which is exactly what `CALL_FUNCTION_RECEIVE_ERROR` describes.
    Both values tried in that record failed because the record should not be there.
  - **The request is single-byte and the response is UTF-16LE.** `"001"` is 3 bytes going
    out and `"A4H"` is 6 coming back. The reply carries `0x0016 = "1100"`, a single-byte
    codepage, while the session's partner codepage is `4103` — the LOGON is exchanged in
    1100 and the session moves to 4103 after it.
  - `0x0130` is the client program name, unpadded; we send an 80-byte padded function
    name.
  Not yet changed in code: the existing builder cites a capture that is not in this tree
  and may be from BTP rather than on-premise, so the two shapes may both be valid for
  their own targets. `wrfc_logon_shape_probe.py` changes one thing at a time to find out
  which difference actually matters before anything is rewritten.

- The GW header table is corrected and most of its unknown fields resolved, by comparing
  85 captured frames rather than reading any one of them more closely. Unknown entries go
  from 14 to 4.
  - **Byte 13 is a frame sequence number**, 1-based within a response, 0 on requests. It
    sat inside five bytes recorded as "zeros / CPIC internal"; four of them are zero and
    the middle one counts — a 22-frame reply numbered its frames 1..22 with no exceptions.
  - **Bytes 30–31 are one BE uint16 position marker**, not two unknown bytes: `0x0108`
    does not complete the response, `0x0100` is a middle frame, `0x050C` completes it. It
    agrees with the independent flag at byte 60 on every frame.
  - **Bytes 52–63 are three BE uint32**, not the "RFC library name + version" the table
    claimed. Twelve bytes read as a padded string, which is why the wrong reading survived.
  - **The field boundary at 16 was one byte early.** Byte 16 is a single flag; 17–20 is the
    BE int32. Split at 16 the int32 reads `0x01000001`/`0x01FFFFFF`, which looks like a
    flags word and is not one.
  - Bytes 8, 11–12, 14–15, 22, 28 and 32–33 are zero in all 85 frames — "always zero in
    everything captured" is a different and more useful claim than "unknown".
- **Tag `0x0503` is the success marker.** Across all ten RFC-layer replies it is present
  exactly when the exception marker `0x0417` is absent. Recorded as "response flag 2,
  meaning unknown"; the meaning comes out of comparing the corpus, which is why no single
  capture ever settled it.


## [0.1.3] - 2026-09-01

A stability and evidence release. No new transport, no new API surface to learn —
the work went into the paths that were already there and into replacing assumptions
with captures.

Three themes run through it:

**Failures that were silent are now loud.** A reply that could not be read to its end
left the connection READY with the remainder still queued, so the *next* call returned
data belonging to different arguments. A response larger than one gateway frame was
truncated rather than reassembled. A pool could hand back a connection whose session was
already dead. Each of those reported nothing at the point it went wrong.

**Facts that were assumed are now sourced.** Uncertainty labels went from 14 to 5, and
the ones removed were not removed by relabelling: DECFLOAT16/34 settled by capture, tag
`0x0667` settled by a probe that separated time from bytes, message variables V2–V4
settled by an exception carrying four distinct values, and the multi-frame continuation
markers settled by a 22-frame reply. Two labels turned out to be *stale rather than
uncertain* — they described behaviour that had since been fixed, which is worse than no
label, because a stale one reads as current fact.

**Several things this library said were wrong.** A free-text tag that no capture had ever
shown. An error code reported as the server's that was hardcoded here. A GW header field
documented as a library-name string that is three integers. Those are corrected in place,
with the evidence recorded next to them.

### Behaviour changes worth knowing

Pre-1.0, so these land without a major bump, but they can surprise:

- **A non-Unicode connection is now refused at handshake** rather than decoding every
  character field as UTF-16BE and returning mojibake. If you connect to a system that
  negotiates anything but codepage `4103`, you now get a clear error instead of plausible
  nonsense. SAP ended support for non-Unicode systems with NetWeaver 7.5.
- **A connection whose reply could not be read is retired permanently.** It used to return
  to READY. Any further call on it raises and names the original fault; open a new one.
- **`AbapApplicationError`'s string carries more.** When the server sends no assembled
  message text — the common case on kernel 793 — it now includes the message class,
  number and variables instead of just the exception key. Code matching on the exact
  string may need updating; the structured fields are unchanged.
- **`ConnectionMetrics.as_dict()` has four new keys** and `PoolMetrics` is new. Additive,
  but code asserting an exact key set will see it.

### Added

- `RfcTrace` writes RFC trace files in the SAP SDK's format (#21), attachable to a
  `Transport` or `AsyncTransport`. The point is diffability: comparing an SDK trace
  against this library's traffic is what identified every defect behind #14, and doing it
  then meant parsing the SDK's output by hand because there was nothing on this side to
  compare with. The hook sits at the transport, so what lands in the file is what crossed
  the socket rather than what some layer intended to send.
  **Credentials are redacted, which the SDK's own traces are not.** A level-4 SDK trace
  dumps the LOGON frame verbatim, and that frame carries tag `0x0117` — the password
  scrambled with a seed travelling beside it, which is obfuscation rather than
  encryption. An SDK trace is therefore a file the password can be recovered from; the
  capture scripts written during #14 scrub them for that reason. `0x0117` values are
  zeroed before anything is written, at unchanged length so every offset still lines up
  with the real frame, and the file's own header says it has been redacted.

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

- The wRFC direct-logon path no longer provokes an ABAP short dump on every connection
  attempt. It parsed the LOGON reply, missed the embedded failure the same way the
  bootstrap path did, and went on to send an invoke into a dead session — which is what
  made the work process dump. It then caught the resulting WebSocket close and fell back
  to classic TCP, so the caller saw the right outcome while the server collected an ST22
  entry each time. Reading the failure first skips the doomed frame.

- `partner_rel` and `kernel_rel` were mojibake on the wRFC path. Every other string tag
  in a wRFC logon reply is decoded UTF-16LE; those two used ASCII, which does not fail
  on UTF-16 input — it returns the NULs interleaved, so `kernel_rel` read
  `'7\x009\x003'` instead of `'793'`. A wrong charset that raises is a bug you find;
  one that returns a plausible-looking string is one you ship. Found by an assertion in
  a test written for something else.

- The wRFC LOGON reply was being read as a success when it carries the failure. Its auth
  tags (`0x0450`–`0x0453`) are filled in whether or not the function call embedded in the
  LOGON ran, so a reply that authenticates and then reports
  `CALL_FUNCTION_RECEIVE_ERROR` looked, to a reader checking only for a sys_id, exactly
  like a clean logon. The library declared the session ready, sent an invoke into it, and
  the work process took a short dump — surfacing as a WebSocket close with
  `RABAX_STATE:Error when receiving data for an RFC.` `_ws_logon_failure` now inspects the
  reply and raises the real exception, with the message class, type and number the server
  sent (`00`/`X`/`341`).
- The `163` in issue #14 is now read from the wire instead of hardcoded. It comes from the
  `0x0418` ABAP call-stack breadcrumb — `;W=SAPLSYSU,E=163,H=3,N=3;S=RFCPING,...` — which
  nothing was parsing. Two sites raised the constant `"163: Error when receiving data for
  an RFC."` instead, and a third used `163` as the fallback for when the server reported
  no return code at all. A hardcoded value that happens to be correct is still a defect:
  it reports 163 for every failure, including the ones that are not 163. Fixture
  `wrfc_logon_receive_error.bin`.
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

[Unreleased]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/randomstr1ng/saprfclib/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/randomstr1ng/saprfclib/releases/tag/v0.1.0
