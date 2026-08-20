# tests/golden/test_fixtures.py
#
# Parametrized test runner for all four gate directories.
# Gate A/B/C tests are placeholders that skip until the respective gates close.

from pathlib import Path

import pytest

from tests.conftest import GOLDEN_ROOT, compare_bytes, discover_fixtures, load_fixture
from tests.golden.serialization._replay import replay_fixture

FRAMING_DIR = GOLDEN_ROOT / "framing"
SERIALIZATION_DIR = GOLDEN_ROOT / "serialization"
HANDSHAKE_DIR = GOLDEN_ROOT / "handshake"
SYNTHETIC_DIR = GOLDEN_ROOT / "synthetic"


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(SYNTHETIC_DIR))
def test_synthetic_fixture_loads(fixture_dir: Path, name: str) -> None:
    """Skeleton test: confirm harness loads and compare_bytes works."""
    fix = load_fixture(fixture_dir, name)
    mismatches = compare_bytes(fix.raw_bytes, fix.raw_bytes, fix.field_annotations)
    assert mismatches == [], mismatches


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(FRAMING_DIR))
def test_framing_replay(fixture_dir: Path, name: str) -> None:
    """Gate A: replay framing fixture byte-for-byte."""
    _ = load_fixture(fixture_dir, name)
    # Executor fills this in: import parser, parse fix.raw_bytes, re-serialize
    # parsed = parse_ni_frame(fix.raw_bytes)
    # regenerated = generate_ni_frame(parsed)
    # mismatches = compare_bytes(regenerated, fix.raw_bytes, fix.field_annotations)
    # assert mismatches == [], mismatches
    pytest.skip("Gate A not yet closed — placeholder")


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(SERIALIZATION_DIR))
def test_serialization_replay(fixture_dir: Path, name: str) -> None:
    """Gate B: replay each serialization fixture byte-for-byte through the codec.

    Shares the exact replay wire-up with
    tests/golden/serialization/test_serialization.py (see _replay.py): confirmed
    scalars replay exactly; BCD/DecFloat/STRUCTURE/TABLE and synthetic fixtures
    are skipped per-type.
    """
    fix = load_fixture(fixture_dir, name)
    regenerated = replay_fixture(fix)
    mismatches = compare_bytes(regenerated, fix.payload_bytes, fix.field_annotations)
    assert mismatches == [], mismatches


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(HANDSHAKE_DIR))
def test_handshake_replay(fixture_dir: Path, name: str) -> None:
    pytest.skip("Gate C not yet closed — placeholder")
