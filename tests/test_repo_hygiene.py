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
    *sorted((ROOT / "tests").glob("*.py")),
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
        r"\b(?:NiI(?:Write|Read)|STI[A-Z]\w+|sec1_\w+)"
    ),
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
    ],
)
def test_patterns_catch_what_they_are_for(line: str) -> None:
    assert any(p.search(line) for p in BANNED.values())
