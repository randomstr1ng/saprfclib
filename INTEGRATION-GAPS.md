
---

## 8. `snc_qop` is unvalidated, and 8 / 9 are not distinguished

Low severity, raised while confirming that dropping `snc_mode` costs nothing. It does
not — `snc_mode` is SAP's 0/1 activation flag and `snc_lib` presence replaces it
exactly. The protection *levels* live in `snc_qop`, which is fully plumbed:
`connect()` → `SncTransport._qop` → the frame dispatch in `SncTransport.send_message`.
Two rough edges in that dispatch:

**No validation.** `connect()` applies `snc_qop or 3` and nothing else looks at the
value again. The dispatch is `>= 3 → PRIVACY`, `== 2 → INTEGRITY`, `else → PLAIN`, so:

| value | result | |
|---|---|---|
| `1` | PLAIN | intended |
| `2` | INTEGRITY | intended |
| `3`–`9` | PRIVACY | `4`–`7` are not SAP QoP values but land on the safe side |
| `0`, `None` | PRIVACY | via `or 3` |
| negative | PLAIN | **unprotected, silently** |

Nothing here is a live security hole — every plausible typo lands on PRIVACY. But a
setting that decides whether payloads are encrypted should not accept a value it does
not recognise. Proposal: validate against `{1, 2, 3, 8, 9}` in `connect()` and raise
`ValueError` on anything else, rather than letting an unrecognised value pick a
protection level by falling through a comparison.

**`8` and `9` collapse into `3`.** SAP defines `8` as "apply the default protection" and
`9` as "apply the maximum protection". `9` → PRIVACY is right. `8` → PRIVACY is a
reasonable guess, not a negotiated answer: the server's default comes from
`snc/data_protection/use`, which the client does not consult. Worth either implementing
the lookup or documenting `8` as an alias for `3` in the `connect()` docstring, so the
approximation is stated rather than inferred from the source.

The `SncQop` IntEnum (`AUTH_ONLY = 1`, `INTEGRITY = 2`, `PRIVACY = 3`) is the natural
home for both — it has no members for `8` / `9` today.
