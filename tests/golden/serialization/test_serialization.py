# tests/golden/serialization/test_serialization.py
#
# Gate B serialization fixture test — runs from tests/golden/serialization/ to satisfy
# `pytest tests/golden/serialization/ -v` acceptance criterion.
# The canonical parametrized runner lives at tests/golden/test_fixtures.py.
#
# Branch B (no live SAP system): fixtures are synthetic (constructed, not captured).
# test_serialization_replay remains skipped until Gate B closes with Wireshark capture.

from pathlib import Path

import pytest

from tests.conftest import GOLDEN_ROOT, compare_bytes, discover_fixtures, load_fixture
from tests.golden.serialization._replay import (
    replay_fixture,
)

SERIALIZATION_DIR = GOLDEN_ROOT / "serialization"


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(SERIALIZATION_DIR))
def test_serialization_fixture_loads(fixture_dir: Path, name: str) -> None:
    """Gate B: confirm synthetic serialization fixtures load without schema errors.

    This test verifies:
    - .json + .bin fixture pairs can be loaded via load_fixture()
    - D-07 schema validation passes (all 5 required keys present)
    - D-12: fixture .bin length matches sum of field_annotations lengths

    Branch B note: fixtures are synthetic (constructed, not captured; no live Wireshark capture).
    Wire byte correctness is marked [ASSUMED] in field_annotations until Gate B
    closes with independent confirmation and live STFC_STRUCTURE capture.
    """
    fix = load_fixture(fixture_dir, name)
    # D-12: verify annotation coverage equals binary length
    annotation_total = sum(a["length"] for a in fix.field_annotations)
    assert annotation_total == len(fix.raw_bytes), (
        f"D-12 violation: annotation bytes ({annotation_total}) != bin size ({len(fix.raw_bytes)})"
    )


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(SERIALIZATION_DIR))
def test_serialization_replay(fixture_dir: Path, name: str) -> None:
    """Gate B: replay serialization fixture byte-for-byte against codec output.

    Decodes the fixture payload through the real saprfclib codec, re-encodes the
    decoded value, and asserts the re-encoded bytes match the .bin payload.
    Confirmed Phase 1 scalar fixtures (type_int4/char/date/time/float/string…)
    replay exactly; not-yet-implemented types (BCD/DecFloat → Plan 04,
    STRUCTURE/TABLE → Plan 03) and synthetic fixtures are skipped per-type.
    """
    fix = load_fixture(fixture_dir, name)
    regenerated = replay_fixture(fix)
    mismatches = compare_bytes(regenerated, fix.payload_bytes, fix.field_annotations)
    assert mismatches == [], mismatches
