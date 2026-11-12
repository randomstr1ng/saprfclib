# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Sources cited in this repository are observations, never SAP internals.

CLAUDE.md: protocol facts are recorded as observed wire behaviour (a capture, a golden
fixture, a live probe) or labelled [ASSUMED]. Internal function, symbol or constant
names of SAP binaries, and "protocol analysis" as a source, must not appear: a fact
that rests only on them is unsourced. This test keeps them from creeping back in.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCANNED = [
    *sorted((ROOT / "src").rglob("*.py")),
    *sorted((ROOT / "docs").rglob("*.md")),
    *sorted((ROOT / "tests").rglob("*.py")),
    *sorted((ROOT / "tests" / "golden").rglob("*.json")),
    ROOT / "README.md",
    ROOT / "CLAUDE.md",
]
SELF = pathlib.Path(__file__).resolve()

# Each pattern names a kind of internal reference; the comment says what it catches.
BANNED = {
    "protocol analysis cited as a source": re.compile(r"protocol analysis", re.I),
    "C++ method of a SAP class": re.compile(r"\b[A-Z][A-Za-z]+::[a-z][A-Za-z]+\b"),
    "SAP-internal constant name": re.compile(r"\bRFCID_[A-Za-z]+"),
    "SAP-internal serializer function": re.compile(
        r"\b(?:writeRfc|readRfc|rfcSupply|rfcDeserial|getNextParameter|readMetadata)\w*"
    ),
    "SAP-internal network/SNC function": re.compile(
        r"\b(?:NiI(?:Write|Read)|STI[A-Z]\w+|GwI[A-Z]\w+|UtilCpy\w+|sec1_\w+)"
    ),
    "SDK header cited as a source": re.compile(r"SDK type definitions|\bh:\d{2,4}\b"),
    "address of the development lab": re.compile(r"\b(?:192\.168\.88|10\.20\.30)\.\d"),
    "SAP-internal versioned class name": re.compile(r"\b[A-Z][A-Z_]+_v\d{1,3}(?:_\d+)?\b"),
    "SAP-internal component name": re.compile(r"\b(?:NgRfc\w*|WebsocketDriver)\b"),
}
# Allowed occurrences: the methodology page's own title, which names the discipline, and
# the CLAUDE.md line that describes this test; neither cites a source.
ALLOWED = {
    ("docs/protocol/methodology.md", "# Protocol Analysis Methodology"),
    (
        "CLAUDE.md",
        'and on "protocol analysis" cited as a source. Cite the capture, fixture or probe instead,',
    ),
}


def _hits() -> list[str]:
    out = []
    for path in SCANNED:
        if path.resolve() == SELF or not path.exists():
            continue
        rel = path.relative_to(ROOT).as_posix()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if (rel, line.strip()) in ALLOWED:
                continue
            for what, pattern in BANNED.items():
                if pattern.search(line):
                    out.append(f"{rel}:{n}: {what}: {line.strip()[:100]}")
    return out


# Docs carry no status labels (docs/protocol/methodology.md, "Evidence Tiers"): an unlabelled
# fact is established and cites its source, [ASSUMED] marks an inference, and what is not
# known is listed under Known Gaps / Open Questions. Labels like CONFIRMED go stale.
DOC_STATUS_LABEL = re.compile(
    r"\b(?:CONFIRMED|UNCONFIRMED|RESOLVED|PARTLY CLOSED)\b|\[UNKNOWN|\*\*(?:Status|Confidence):"
    r"|^#{2,6} .* — (?:OPEN|CLOSED|PARTIAL)\b"
)
DOCS = [*sorted((ROOT / "docs").rglob("*.md")), ROOT / "README.md"]


def test_docs_carry_no_status_labels() -> None:
    hits = [
        f"{p.relative_to(ROOT).as_posix()}:{n}: {line.strip()[:100]}"
        for p in DOCS
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if DOC_STATUS_LABEL.search(line)
    ]
    assert not hits, "\n".join(hits)


def test_no_internal_references_cited_as_sources() -> None:
    hits = _hits()
    assert not hits, "\n".join(hits)


@pytest.mark.parametrize(
    "line",
    [
        "# confirmed by protocol analysis of the serializer",
        "see RfcFunction::serialize",
        "(RFCID_TableContent)",
        "NiIWrite bswap",
        "the NgRfc stream",
        "STIInit [10]=1",
        "GwIConnect kind=0xb",
        "(SDK type definitions-332)",
        "see h:2272",
        "DDIF_FIELDINFO_GET_v462_6",
    ],
)
def test_patterns_catch_what_they_are_for(line: str) -> None:
    assert any(p.search(line) for p in BANNED.values())


# Binary fixtures are sanitised with length-preserving substitutions (CLAUDE.md); the lab
# network must not survive in any encoding a capture can carry it in.
_LAB_BYTES = [
    form
    for text in ("192.168.88.", "10.20.30.")
    for form in (text.encode("ascii"), text.encode("utf-16-le"))
] + [bytes([192, 168, 88]), bytes([10, 20, 30])]


@pytest.mark.parametrize(
    "path",
    sorted((ROOT / "tests" / "golden").rglob("*.bin")),
    ids=lambda p: p.relative_to(ROOT).as_posix(),
)
def test_binary_fixtures_carry_no_lab_address(path: pathlib.Path) -> None:
    data = path.read_bytes()
    assert not [f for f in _LAB_BYTES if f in data]
