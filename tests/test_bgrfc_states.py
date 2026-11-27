# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The STATE BGRFC_CHECK_UNIT_STATE_SERVER answers at each point of a unit's life.

Replays tests/golden/trfc/bgrfc_states.json, read live from units saprfclib submitted.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from saprfclib.connection import _strip_gw_header
from saprfclib.invoke import _extract_name_value_pairs, unit_state_from_wire, unit_state_to_wire

FX = json.loads((Path(__file__).parent / "golden" / "trfc" / "bgrfc_states.json").read_text())

EXPECTED = {
    "never_submitted": "NOT_FOUND",
    "running": "IN_PROCESS",
    "committed": "COMMITTED",
    "confirmed": "CONFIRMED",
    "failed": "ROLLED_BACK",
}


def _state(case: str) -> int:
    tlv = b"".join(_strip_gw_header(bytes.fromhex(h)) for h in FX["cases"][case]["reply_hex"])
    (value,) = struct.unpack("<i", dict(_extract_name_value_pairs(tlv))["STATE"])
    return int(value)


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_each_live_state_is_read_and_named(case: str) -> None:
    value = _state(case)
    assert value == FX["cases"][case]["state"]
    assert unit_state_from_wire(value) == (EXPECTED[case], True)
    assert unit_state_to_wire(EXPECTED[case]) == value


def test_a_state_never_seen_is_not_given_a_name() -> None:
    assert unit_state_from_wire(22209) == ("22209", False)
