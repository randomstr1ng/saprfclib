# tests/golden/serialization/_replay.py
#
# Shared fixture-replay logic for the Gate B serialization golden fixtures.
#
# Both tests/golden/serialization/test_serialization.py and
# tests/golden/test_fixtures.py drive the SAME replay (the plan requires the two
# runners to stay identical), so the wire-up lives here once.
#
# replay_fixture() rebuilds a FieldDesc from a fixture's expected_parse, decodes
# the fixture payload through the real saprfclib codec, re-encodes the decoded
# value, and returns the re-encoded bytes for byte-for-byte comparison against
# the .bin payload. BCD (Plan 04, this plan) now replays through the codec via
# the scalar field path (digit count derived from wire_size_bytes). DecFloat16/34
# stay skipped — GAP-B-01 documents the unconfirmed wire form (no live capture),
# so the codec raises NotImplementedError by design and there is no .bin to
# replay (type_decf16_GAP.json is marker-only). STRUCTURE/TABLE are descriptor-
# driven (they need a TypeDesc the scalar field_from_fixture can't build) and are
# validated by their dedicated tests in tests/test_codec.py, so this scalar
# replay path skips them.

from __future__ import annotations

import pytest

from saprfclib import decode, encode
from saprfclib.types import FieldDesc

# RFCTYPE values this scalar replay path does not handle — skip them here.
# BCD (2) is now implemented and replays normally. DecFloat16/34 remain the
# documented GAP-B-01 gap (no live bytes; codec raises). STRUCTURE (17) / TABLE
# (5) are descriptor-driven and covered by dedicated tests, not scalar replay.
NOT_YET_IMPLEMENTED: dict[int, str] = {
    23: "GAP-B-01 (DecFloat16 — wire form unconfirmed, no live capture)",
    24: "GAP-B-01 (DecFloat34 — wire form unconfirmed, no live capture)",
    17: "STRUCTURE — descriptor-driven, covered by tests/test_codec.py",
    5: "TABLE — descriptor-driven, covered by tests/test_codec.py",
}

# The standard per-type skip tag for synthetic / assumed fixtures.
SYNTHETIC_SKIP_MESSAGE = (
    "ASSUMED (synthetic) — replace with live capture fixture to remove this tag"
)


def _is_synthetic(fix) -> bool:
    """True when a fixture's gap_status marks it ASSUMED / synthetic.

    BCD/DecFloat replay must not run against an unconfirmed (synthetic) fixture
    until a live capture is present (status != synthetic). gap_status lives in
    the fixture JSON; load_fixture does not surface it, so we read capture_source
    and the (optional) gap marker text instead.
    """
    blob = f"{getattr(fix, 'capture_source', '')}".lower()
    return "synthetic" in blob or "assumed" in blob


def field_from_fixture(fix) -> FieldDesc:
    """Build a scalar FieldDesc from a fixture's expected_parse block.

    Maps rfctype_value → rfctype and wire_size_bytes → uc_length (the Unicode
    wire byte width). For SAP_UC fixed-width types (CHAR/NUM/DATE/TIME) the char
    count is uc_length // 2 (Pitfall 1). Variable-length types (STRING/XSTRING)
    carry their length on the wire, so uc_length is informational only.
    """
    ep = fix.expected_parse
    rfctype = ep["rfctype_value"]
    wire_size = ep.get("wire_size_bytes", 0) or 0
    decimals = ep.get("decimals", 0) or 0
    return FieldDesc(
        name=ep.get("rfctype", "F"),
        rfctype=rfctype,
        nuc_length=wire_size,
        nuc_offset=0,
        uc_length=wire_size,
        uc_offset=0,
        decimals=decimals,
        unicode_mode=True,  # Phase 2 wire mode is UTF-16-LE (D-09)
    )


def replay_fixture(fix) -> bytes:
    """Decode then re-encode a fixture payload through the codec.

    Returns the re-encoded bytes. Raises pytest.skip.Exception (via
    pytest.skip) for fixtures whose codec is not implemented in this plan, or
    for synthetic BCD/DecFloat fixtures awaiting a live capture.
    """
    ep = fix.expected_parse
    if ep is None:
        pytest.skip("documentation-only marker fixture (no expected_parse)")

    rfctype = ep["rfctype_value"]

    if rfctype in NOT_YET_IMPLEMENTED:
        # BCD specifically: only skip while synthetic; a live-captured BCD
        # fixture is still deferred to Plan 04, so skip regardless here, but
        # carry the synthetic tag when applicable for traceability.
        if _is_synthetic(fix):
            pytest.skip(f"{SYNTHETIC_SKIP_MESSAGE} — {NOT_YET_IMPLEMENTED[rfctype]}")
        pytest.skip(f"codec deferred to {NOT_YET_IMPLEMENTED[rfctype]}")

    field = field_from_fixture(fix)
    value = decode(rfctype, fix.payload_bytes, field)
    return encode(rfctype, value, field)
