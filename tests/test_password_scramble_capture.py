# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The 0x0117 password record, replayed from tests/golden/handshake/password_scramble.json."""

from __future__ import annotations

import json
import pathlib
import struct

import pytest

from saprfclib.connection import _ab_scramble, _scramble_password

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "handshake" / "password_scramble.json").read_text(
        encoding="utf-8"
    )
)


@pytest.mark.parametrize("case", FX["records"], ids=lambda c: str(len(c["password"])))
def test_reference_record_descrambles_to_the_password(case: dict) -> None:
    record = bytes.fromhex(case["record"])
    seed = struct.unpack("<I", record[:4])[0]
    body = bytearray(record[4:])
    _ab_scramble(body, seed)
    assert bytes(body) == case["password"].encode("ascii")


@pytest.mark.parametrize("case", FX["records"], ids=lambda c: str(len(c["password"])))
def test_scrambling_reproduces_the_reference_record(case: dict) -> None:
    record = bytes.fromhex(case["record"])
    seed = struct.unpack("<I", record[:4])[0]
    assert _scramble_password(case["password"], seed=seed) == record
