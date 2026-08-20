# Contributing to saprfclib

Thanks for considering a contribution. This project reimplements a proprietary wire
protocol from observed behaviour, so it has one unusual rule that overrides normal
"make it work" instincts: **evidence before code**. Please read
[CLAUDE.md](CLAUDE.md) before your first protocol change — it is short and it explains
why a plausible-looking patch can still be rejected.

## Licence of Contributions

`saprfclib` is licensed under the **Mozilla Public License 2.0**. By submitting a pull
request you agree that your contribution is licensed under MPL-2.0. New source files
must carry the standard MPL header:

```python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
```

Do not contribute code, constants, tables, or documentation copied from the SAP
NetWeaver RFC SDK, from SAP documentation behind a licence agreement, or from any
other project whose licence is incompatible with MPL-2.0. See "Protocol Evidence"
below for what is acceptable.

## Development Setup

**Prerequisites:** Python 3.12+, git, hatch (`pip install hatch`).

```bash
git clone https://github.com/randomstr1ng/saprfclib
cd saprfclib

# Option A — editable install into the active env
pip install -e ".[dev]"

# Option B — hatch-managed envs (recommended)
hatch env create default
```

> `hatch-vcs` derives the version from git tags. If you build from a shallow clone or
> a tarball with no git metadata, the version falls back to `0.0.0.dev0`.

Run offline tests:

```bash
hatch run test -m "not integration"
```

Lint and format:

```bash
hatch run lint:check   # check only (CI mode)
hatch run lint:fmt     # apply fixes
```

Type-check:

```bash
hatch run lint:type
```

Build docs locally:

```bash
hatch run docs:build   # produces site/
hatch run docs:serve   # live reload at http://127.0.0.1:8000
```

## Protocol Evidence

Any change to wire behaviour — framing, field offsets, type serialization, handshake
order, constants — must cite its evidence in the pull request description and in a
code comment. Acceptable evidence, strongest first:

1. **Live capture.** A pcap from your own SAP system showing the bytes. Add a golden
   fixture under `tests/golden/` and a test that asserts byte equality.
2. **Behavioural observation.** A documented request/response pair showing what the
   server accepts or rejects.
3. **Inference from an existing confirmed field.** Must be labelled `[ASSUMED]` in
   both the code comment and the protocol docs until a capture confirms it.

Not acceptable: "this value looks right", "pyrfc seems to do this", or any constant
without a stated source. An unsourced magic number will be sent back.

Golden fixtures are ground truth. If a change makes a golden test fail, the default
assumption is that the change is wrong — not the fixture. Fixtures are only replaced
when a new capture proves the old one was misread, and the PR must say so explicitly.

Captured fixtures must not contain real credentials, real internal hostnames, or
customer data. Where a fixture had to be sanitised, the substitution is noted in the
test docstring and preserves the original byte length so offsets stay valid.

## Running Tests Against a Live SAP System

Integration tests are marked `integration` and are deselected in CI — the public CI
has no SAP system. To run them locally, set:

```bash
export SAPRFC_ASHOST=your-as-host
export SAPRFC_SYSNR=00
export SAPRFC_CLIENT=001
export SAPRFC_USER=your-user
export SAPRFC_PASSWD=your-password
```

Optional (message server logon):

```bash
export SAPRFC_MSHOST=your-ms-host
export SAPRFC_SYSID=A4H
export SAPRFC_GROUP=PUBLIC
```

Optional (WebSocket RFC):

```bash
export SAPRFC_WSHOST=your-ws-host
```

Optional (SNC):

```bash
export SAPRFC_SNC_LIB=/path/to/libsapcrypto.so
export SAPRFC_SNC_PARTNERNAME=p:CN=your-partner
```

Then run the full suite including live integration tests:

```bash
hatch run test
# or
pytest
```

Never commit connection parameters, credentials, or system identifiers. See
`tests/conftest.py` for the full list of variables.

## Code Style

[Ruff](https://docs.astral.sh/ruff/) is the linter and formatter (replaces flake8 +
black + isort). All code must pass `hatch run lint:check` before merging. Type
annotations are required on all public APIs; mypy strict mode is enforced via
`hatch run lint:type`.

Zero non-Python runtime dependencies is a hard project constraint — do not add C
extensions, ctypes-wrapped vendor binaries, or third-party native deps to the core
package. `wsproto` and `h11` are the only runtime dependencies and both are pure
Python.

## Pull Requests

1. Branch from `main`.
2. Keep the change focused; protocol changes and refactors go in separate PRs.
3. Add or update tests. Protocol changes need a golden fixture or an explicit
   `[ASSUMED]` label.
4. Update `docs/protocol/` when wire behaviour changes, and `CHANGELOG.md` under
   "Unreleased".
5. Ensure `hatch run lint:check`, `hatch run lint:type`, and
   `hatch run test -m "not integration"` all pass.

## Security Issues

Do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md).

## Release Process (Maintainers Only)

Releases are tag-driven. `hatch-vcs` derives the package version from the git tag, and
publishing to PyPI uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
— there is no API token stored in the repository.

1. Ensure CI is green on `main`.

2. Update `CHANGELOG.md`: move "Unreleased" entries under the new version heading.

3. Tag with semantic versioning:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. The `publish` workflow triggers on the `v*` tag. It builds the wheel + sdist,
   publishes to TestPyPI, then waits for manual approval of the `pypi` GitHub
   environment before publishing to PyPI.

5. Approve the deployment in the GitHub Actions run.

6. Verify:

   ```bash
   pip install saprfclib==0.2.0
   python3 -c "import saprfclib; print(saprfclib.__version__)"
   ```

7. Docs deploy automatically to GitHub Pages on every push to `main`.
