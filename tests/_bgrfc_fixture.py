# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Descriptors for bgRFC tests, from the server replies in bgrfc_saprfclib.json."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

from saprfclib.connection import Connection
from saprfclib.types import FunctionDesc

from ._mocks import MockTransport

_FIXTURE = Path(__file__).parent / "golden" / "trfc" / "bgrfc_saprfclib.json"

# The order in which the captured session asked: BGRFC_DEST_SHIP's interface and its
# four DDIC lookups, then STFC_CONNECTION's interface.
_SHIP_REPLIES = slice(0, 5)
_STFC_REPLY = 5


def _replies() -> list[bytes]:
    return [bytes.fromhex(h) for h in json.loads(_FIXTURE.read_text())["replies_hex"]]


@cache
def descriptors() -> dict[str, FunctionDesc]:
    from .test_connection import _handshake_responses

    replies = _replies()
    transport = MockTransport(
        _handshake_responses() + replies[_SHIP_REPLIES] + [replies[_STFC_REPLY]]
    )
    conn = Connection(transport)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    return {
        "BGRFC_DEST_SHIP": conn._call_bootstrap("BGRFC_DEST_SHIP"),
        "STFC_CONNECTION": conn._call_bootstrap("STFC_CONNECTION"),
    }
