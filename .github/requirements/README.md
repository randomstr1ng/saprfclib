# CI tool requirements

Exact, hash-locked versions of the tools the workflows install: `hatch.txt`
(ci, docs, publish), `semgrep.txt` and `zizmor.txt` (security). The workflows
install them with `pip install --require-hashes --only-binary=:all: -r ...`, so
a new upstream release cannot run in CI until it has been reviewed here.

To change a version, edit the `.in` file and regenerate the `.txt` with the
command in its header, for example:

```sh
uv pip compile --universal --generate-hashes --python-version 3.12 \
  .github/requirements/hatch.in -o .github/requirements/hatch.txt
```

`--universal` matters for `hatch.txt`: CI runs it on Linux, Windows and macOS.

Trivy is not a Python package. Its version and SHA-256 are pinned in
`.github/workflows/security.yml`, and are bumped by hand.
