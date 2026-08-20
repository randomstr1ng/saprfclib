## What this changes

<!-- One or two sentences. -->

## Evidence (required for any wire-behaviour change)

<!--
State the source for every wire value you added or changed. See CLAUDE.md.
Delete this section only if the PR touches no protocol behaviour.
-->

- [ ] Live capture / golden fixture — fixture path:
- [ ] Behavioural probe against a live system — describe:
- [ ] Inference from a confirmed field — labelled `[ASSUMED]` in code and docs

## Checklist

- [ ] `hatch run test -m "not integration"` passes
- [ ] `hatch run lint:check` passes
- [ ] `hatch run lint:type` passes
- [ ] No golden fixture was edited to make a test pass
- [ ] No new non-Python runtime dependency
- [ ] No SAP source, headers, binaries, or decompiler output added
- [ ] `docs/protocol/` updated if wire behaviour changed
- [ ] `CHANGELOG.md` updated under "Unreleased"
- [ ] New source files carry the MPL-2.0 header
