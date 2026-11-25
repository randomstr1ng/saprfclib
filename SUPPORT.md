# Support

## What is supported

The table under [What works, and what doesn't](README.md#what-works-and-what-doesnt)
in the README is the support boundary. Its groups:

- **Supported**: verified against a live SAP system, by a capture, a golden fixture or an
  integration test.
- **Preview**: implemented and tested offline, but not live-verified, or verified with
  documented open gaps. Use it, test it against your system, and expect changes in a
  minor release.
- **Not implemented** and **refused**: not available. A refused case raises a clear
  error on purpose; that is the library working, not a bug.

The public API carries the same labels, per name, in
[`tests/api/public_api.json`](tests/api/public_api.json).

## Versions

- **saprfclib:** the latest release on [PyPI](https://pypi.org/project/saprfclib/). The
  project is pre-1.0; fixes land on `main` and ship as a new release. A git checkout is
  fine for trying a fix, but a report should name the commit.
- **Python:** CPython 3.12 or later. CI runs the offline suite on 3.12, 3.13, 3.14 and
  3.15 on Linux, on 3.12 and 3.15 on Windows and macOS, and on the free-threaded 3.15t
  build on Linux.
- **SAP systems:** Unicode systems (codepage 4103) only. Live captures in this repository
  come from SAP NetWeaver 7.52, S/4HANA 2023 (SAP_BASIS 758, kernel 793) and ABAP
  Platform 2025 (SAP_BASIS 816, kernel 916). Other releases are expected to work, but
  only these are evidence; a capture from another release is a welcome contribution.

CI runs only the offline suite. Live verification is done against the maintainer's own
systems and recorded as captures under `tests/golden/`, which CI then replays.

## Getting help

- **A bug:** open an issue with the bug report template. It asks for the facts a
  maintainer needs and shows how to describe a failure without any data from your system.
- **A missing feature or a protocol gap:** use the feature request or protocol gap
  template. Check the open issues first; a capture may already be what blocks it.
- **Usage questions:** the [documentation](https://randomstr1ng.github.io/saprfclib/)
  covers connection options, error handling, migrating from pyrfc, and the wire protocol.
  If it does not answer your question, an issue is fine.
- **A security problem:** never open a public issue. Report it privately as described in
  [SECURITY.md](SECURITY.md).

saprfclib is an independent project. It is not affiliated with or supported by SAP;
questions about your SAP system itself go to SAP.
