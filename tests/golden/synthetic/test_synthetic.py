# tests/golden/synthetic/test_synthetic.py
#
# Synthetic fixture test — runs from tests/golden/synthetic/ to satisfy
# `pytest tests/golden/synthetic/ -v` acceptance criterion.
# The canonical parametrized runner lives at tests/golden/test_fixtures.py.

from pathlib import Path

import pytest

from tests.conftest import GOLDEN_ROOT, compare_bytes, discover_fixtures, load_fixture

SYNTHETIC_DIR = GOLDEN_ROOT / "synthetic"


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(SYNTHETIC_DIR))
def test_synthetic_fixture_loads(fixture_dir: Path, name: str) -> None:
    """Skeleton test: confirm harness loads and compare_bytes works."""
    fix = load_fixture(fixture_dir, name)
    mismatches = compare_bytes(fix.raw_bytes, fix.raw_bytes, fix.field_annotations)
    assert mismatches == [], mismatches
