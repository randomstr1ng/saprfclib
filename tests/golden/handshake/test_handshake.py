# tests/golden/handshake/test_handshake.py
#
# Gate C handshake fixture tests — runs from tests/golden/handshake/ to satisfy
# `pytest tests/golden/handshake/ -v` acceptance criterion.

from pathlib import Path

import pytest

from tests.conftest import GOLDEN_ROOT, discover_fixtures, load_fixture

HANDSHAKE_DIR = GOLDEN_ROOT / "handshake"


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(HANDSHAKE_DIR))
def test_handshake_fixture_loads(fixture_dir: Path, name: str) -> None:
    """Gate C: confirm handshake fixtures load without schema errors.

    Verifies:
    - .json + .bin fixture pairs load via load_fixture()
    - D-07 schema validation passes (all 5 required keys present)
    - D-12: fixture .bin length == sum of field_annotations lengths
    """
    fix = load_fixture(fixture_dir, name)
    annotation_total = sum(a["length"] for a in fix.field_annotations)
    assert annotation_total == len(fix.raw_bytes), (
        f"D-12 violation: annotation bytes ({annotation_total}) != bin size ({len(fix.raw_bytes)})"
    )


@pytest.mark.parametrize("fixture_dir,name", discover_fixtures(HANDSHAKE_DIR))
def test_handshake_replay(fixture_dir: Path, name: str) -> None:
    """Gate C: replay handshake fixture byte-for-byte against encoder output.

    Gate C fixture data confirmed from live capture 2026-06-26.
    Replay assertions activate once the saprfclib handshake module is implemented (Phase 3+).
    """
    pytest.skip("Gate C fixtures confirmed; handshake encoder implementation pending (Phase 3+)")
