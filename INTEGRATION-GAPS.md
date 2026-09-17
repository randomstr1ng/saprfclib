# Integration gaps

Things downstream integrations needed from `saprfclib` and could not get from the
public API. Each entry records what was wanted, what had to be done instead, and a
concrete proposal. This is a backlog note, not user documentation — it is deliberately
outside `docs/` and not in the mkdocs nav.

**Open: none.** The eight entries raised so far are closed; where each landed is below,
so a downstream workaround can be retired against a specific release rather than
guessed at.

Add new entries above this line as they come up.

---

## Closed

Source of entries 1–8: porting the FortiSOAR "SAP NetWeaver" connector (`sap-rfc`
v2.0.0) off `pyrfc`.

| # | Gap | Closed by |
|---|-----|-----------|
| 1 | Function metadata dropped `OPTIONAL`, `DEFAULT`, `PARAMTEXT` | `FieldDesc.optional`, `.default_value`, `.param_text`; `get_function_desc()` exported from the package root |
| 2 | No gateway port override | `port=` on `connect()` and `connect_async()` |
| 3 | `Connection` had no sync context-manager protocol | `__enter__` / `__exit__` |
| 4 | No pyrfc-compatible exception names | `saprfclib.compat` |
| 5 | No `jsonable()` helper | `saprfclib.jsonable()` |
| 6 | No pyrfc migration guide | `docs/getting-started/migrating-from-pyrfc.md` |
| 7 | *(not a gap)* `strict_params=False` is the right default | unchanged, deliberately |
| 8 | `snc_qop` unvalidated; `8`/`9` not distinguished | `validate_snc_qop()`, `SncQop.DEFAULT`/`MAXIMUM`, table dispatch |

Two of these are worth remembering rather than just recording.

**Entry 8 was the only one with a security edge.** The dispatch read
`>= 3 → PRIVACY`, `== 2 → INTEGRITY`, `else → PLAIN`. Undefined values 4–7 landed on
privacy — the safe side, and why it went unnoticed — but a negative number fell past
both comparisons into the `else` and sent payloads **unprotected, silently**, on a
connection the caller had asked to protect. The fix that matters is not the validation
but the shape: the dispatch is now a table, and a table cannot fall through, so `PLAIN`
is reachable only from QOP 1 rather than being the destination for anything
unrecognised.

**`SncQop.DEFAULT` (8) remains an approximation, and is labelled `[ASSUMED]`.** SAP
defines it as "the system's default protection", which lives in the server's
`snc/data_protection/use` profile parameter. This library does not read that parameter,
so 8 is treated as 3. It errs toward more protection, the only direction it is safe to
approximate in, and the approximation is stated in `connect()`'s docstring rather than
left to be inferred from the source. Reading that parameter over RFC would settle it.
