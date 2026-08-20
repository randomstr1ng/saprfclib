# CLAUDE.md — working rules for `saprfclib`

Guidance for Claude Code and any other agent or contributor working in this repository.
Read this before changing anything under `src/saprfclib/`.

---

## What this project is

`saprfclib` is a pure-Python reimplementation of the SAP RFC wire protocol — client and
server — with zero native dependencies. The entire value of the project is that
`pip install saprfclib` is enough: no SAP NetWeaver RFC SDK, no C compiler, no
`LD_LIBRARY_PATH`, no vendor `.so`.

Everything below exists to protect two things: **that constraint**, and **the accuracy
of the protocol implementation**.

---

## The prime rule: evidence before code

This is a reimplementation of an undocumented, proprietary protocol. The normal
software instinct — "try a value, see if it works, move on" — produces code that passes
tests today and corrupts financial data on a customer's system next year.

**Never guess a wire value.** Not a field offset, not a length, not a constant, not a
byte order, not a padding rule.

Every wire-level value must be traceable to a source, and the source must be stated in
a comment next to the value. Sources, strongest first:

| Tier | Source | Use |
|------|--------|-----|
| 1 | **Live capture** — bytes observed on the wire from a real SAP system | Ground truth. Overrides everything else, including this document. |
| 2 | **Golden fixture** — a capture committed under `tests/golden/` | Ground truth, replayable in CI. |
| 3 | **Behavioural probe** — what a live server accepts or rejects | Confirms semantics, not exact bytes. |
| 4 | **Inference** from an already-confirmed neighbouring field | Allowed only when labelled `[ASSUMED]`. |

If you cannot reach tier 1–3 for a value, you have two legitimate options:

1. Label it `[ASSUMED]` in the code comment **and** in `docs/protocol/`, and say so in
   the PR.
2. Document the gap and stop.

You do not have a third option. Shipping an unsourced constant is worse than shipping
nothing — a missing feature is visible, a wrong byte is not.

### What "document the gap" means

Leave the code path raising a clear error naming what is unknown, add the open question
to the relevant `docs/protocol/*.md`, and move on. A loud `NotImplementedError` with an
explanation beats a plausible value that silently mis-serializes a decimal.

---

## Golden fixtures are ground truth

`tests/golden/` holds byte-exact frames captured from live SAP systems, each paired with
a `.json` describing the field breakdown.

- If a change makes a golden test fail, **the change is wrong** until proven otherwise.
  Do not edit a fixture to make a test pass. That inverts the entire evidence model.
- A fixture may only be replaced when a new capture proves the old one was misread, and
  the PR must state that explicitly.
- Fixtures are sanitised of real credentials and internal hostnames. Sanitisation
  **preserves byte length** so every offset and length field stays valid — see the
  substitution note in `tests/test_router.py`. Follow that pattern; never change a
  fixture's length to scrub it.
- New protocol work should arrive with a new fixture. A protocol change with no fixture
  and no `[ASSUMED]` label is not reviewable.

---

## Hard constraints

- **Zero non-Python runtime dependencies.** Only `wsproto` and `h11`, both pure Python,
  both core (not extras). Never add a C extension, a ctypes wrapper around a vendor
  binary, `cryptography`, `numpy`, `aiohttp`, or anything requiring a build step.
  `tests/test_packaging.py` enforces the dependency contract — if it goes red, the
  contract was broken, not the test.
- **Never link or wrap `libsapnwrfc.so`.** That is `pyrfc`, and it is precisely what
  this project exists to avoid.
- **Python 3.12+ only.** No backports, no compatibility shims. Use modern syntax freely.
- **stdlib `ssl` and `hashlib` are fine** — they are C-backed but part of CPython, so
  they do not violate the constraint. Third-party native code does.
- **Thread safety.** A `Connection` is owned by one thread or task at a time; the pool
  is the concurrency boundary. Prefer that ownership model over fine-grained locking
  inside a connection.
- **Never log secrets.** Passwords, SNC tokens, and session tokens must not reach a log
  record at any level. Check this whenever you touch a `_logger` call near auth.

---

## Legal boundary — do not cross it

This repository must contain **no SAP material**:

- no SAP source code, headers (`sapnwrfc.h`, `sapucrfc.h`, `sapdecf.h`), binaries, or
  libraries;
- no verbatim tables, enum listings, or text copied out of the SDK or from SAP
  documentation covered by a licence agreement;
- no decompiler output, and no addresses or symbol offsets from `libsapnwrfc.so`.

Protocol knowledge in this repo is expressed as observed wire behaviour, derived from
captures of the authors' own systems for interoperability purposes. Keep it that way.
If a fact can only be justified by pointing at a decompiled SAP binary, it does not
belong in a comment or in `docs/protocol/` — treat it as unsourced.

Private research artifacts stay in the private development repository. They are not
migrated here, and nothing here should link to them.

---

## Architecture

Sans-I/O core, thin I/O shells. The protocol logic must be testable without sockets —
that is what lets golden fixtures drive the state machines directly.

```
src/saprfclib/
  types.py           descriptor dataclasses (field/type/function metadata)
  codec.py           ABAP type encode/decode, keyed on RFCTYPE  — sans-I/O
  compress.py        SAPCOMPRESS (LZH/LZC) + SAP LZ4 frames     — sans-I/O
  invoke.py          RFC call TLV builder + response parser     — sans-I/O
  session.py         client RFC session state machine           — sans-I/O
  server_session.py  server-side registration/listen machine    — sans-I/O
  snc.py             SNC frame codec + GSS-API binding (ctypes to user-supplied lib)
  transport.py       blocking NI/TCP socket transport (4-byte BE length prefix)
  ws.py              WebSocket RFC transport (wsproto + h11 over ssl)
  router.py          SAProuter route strings, message-server group logon
  connection.py      sync Connection facade — binds transport + session
  pool.py            thread-safe bounded connection pool
  server.py          RFC server: sans-I/O dispatch + asyncio serve facade
  metadata.py        DDIC function metadata fetch + in-process cache
  stores.py          tRFC/qRFC/bgRFC durable-store protocols
  exceptions.py      public typed exception hierarchy
```

Layer discipline: `transport.py` owns the NI length prefix and nothing above it.
`session.py` owns the handshake and the TLV stream. `connection.py` orchestrates; it
should not parse bytes itself. Keep new protocol logic in the sans-I/O layer.

---

## Protocol pitfalls that have already bitten

- **UTF-16 length is in code units, not `len(str)`.** `SAP_UC` is `char16_t`. A fixed
  `RFC_DATE[8]` is 8 code units = 16 bytes. Doubling or halving in the wrong place is
  the single most common bug class here.
- **Always use explicit `utf-16-le` / `utf-16-be`.** Never bare `utf-16` — it emits and
  consumes a BOM the wire format does not have.
- **Never use `float` for ABAP packed/decimal types.** Binary float cannot represent
  base-10 decimals exactly; this corrupts financial values. `decimal.Decimal` for
  values, the in-tree BCD/DPD codec for the wire encoding.
- **The gateway port is `3300 + sysnr`, not 3200.** Captures on 3200 (dispatcher) yield
  nothing.
- **Byte order is per-field, not global.** Confirm each field rather than assuming the
  connection's negotiated endianness applies.
- **Fixed-width character fields are blank-padded, numeric fields zero-padded.** Not
  interchangeable.

---

## Testing

```bash
hatch run test -m "not integration"   # offline suite — must be green before any PR
hatch run lint:check                  # ruff lint + format check
hatch run lint:type                   # mypy strict over src/
```

- The offline suite is the CI gate; it needs no SAP system.
- Tests marked `integration` need a live SAP system via `SAPRFC_*` environment
  variables and are deselected in CI. Never make an offline test depend on a network.
- Hypothesis property tests guard the codecs — `decode(encode(x)) == x` catches the
  round-trip mistakes example-based tests miss. Add properties when you add a type.
- mypy runs in strict mode over `src/`. Public APIs require full annotations.
- Do not weaken a test to make a change pass. Do not add `# type: ignore` without a
  comment saying why.

---

## Conventions

- Ruff is the linter and formatter — line length 100, target py312.
- New source files carry the MPL-2.0 header (see `CONTRIBUTING.md`).
- Comments explaining a wire value cite their evidence inline, e.g.
  `# 0x0514 — session token, 16B binary. Source: golden fixture stfc_connection_request.bin`.
- Decisions carry `D-nn` identifiers in comments; keep referencing them when you touch
  the code they justify.
- Uncertainty is labelled `[ASSUMED]` — searchable on purpose. Do not remove the label
  without capture evidence.
- Environment variables keep the `SAPRFC_` prefix; they describe SAP connection
  parameters, not the library.
- Version comes from git tags via `hatch-vcs`. Never hand-edit a version string.

---

## Working style in this repo

- Read the relevant `docs/protocol/*.md` before changing wire behaviour, and update it
  in the same PR when behaviour changes.
- Prefer a narrow, well-evidenced change over a broad plausible one.
- When a capture contradicts this document, the capture wins — and update this document.
- Never commit or push on behalf of the maintainer unless explicitly asked in that
  session.
