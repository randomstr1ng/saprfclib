# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""check_metadata() finds interfaces the server reports as changed (#112).

Live probe, ABAP Platform 2025 (docs/protocol/framing.md): changing only a structure
a function uses left the function's RFC_METADATA_GET change date (UDAT/UTIME) where
it was and moved the DATATYPESCONT-TIMESTAMP of that structure and of the structure
containing it. The values below are the ones that probe read.
"""

from __future__ import annotations

from typing import Any

import pytest

from saprfclib.codec import RFCTYPE_CHAR, RFCTYPE_STRUCTURE
from saprfclib.connection import (
    Connection,
    _descriptor_type_names,
    _metadata_get_params,
    _metadata_stamp,
)
from saprfclib.metadata import MetadataCache
from saprfclib.pool import ConnectionPool
from saprfclib.types import FieldDesc, FunctionDesc, TypeDesc

from ._mocks import MockTransport
from .test_connection import _handshake_responses


def _desc() -> FunctionDesc:
    flat = TypeDesc("ZSAPRFCLIB_FLAT", [FieldDesc("C", RFCTYPE_CHAR, 10, 0, 20, 0, 0)], 10, 20)
    deep = TypeDesc(
        "ZSAPRFCLIB_DEEP",
        [FieldDesc("FLAT", RFCTYPE_STRUCTURE, 10, 0, 20, 0, 0, type_desc=flat)],
        10,
        20,
    )
    return FunctionDesc(
        "Z_SAPRFCLIB_DEEP",
        [
            FieldDesc("IS_DEEP", RFCTYPE_STRUCTURE, 0, 0, 240, 0, 0, type_desc=deep),
            FieldDesc("IS_FLAT", RFCTYPE_STRUCTURE, 0, 0, 144, 0, 0, type_desc=flat),
        ],
    )


def _reply(
    flat_ts: str, deep_ts: str, udat: str = "20261126", utime: str = "115530"
) -> dict[str, Any]:
    return {
        "FUNCTIONNAMES": [{"FUNCTIONNAME": "Z_SAPRFCLIB_DEEP", "UDAT": udat, "UTIME": utime}],
        "DATATYPESCONT": [
            {"TYPENAME": "ZSAPRFCLIB_FLAT", "TIMESTAMP": flat_ts},
            {"TYPENAME": "ZSAPRFCLIB_FLAT", "TIMESTAMP": flat_ts},
            {"TYPENAME": "ZSAPRFCLIB_DEEP", "TIMESTAMP": deep_ts},
        ],
        "FUNC_ERRORS": [],
    }


BEFORE = _reply("20261126115321", "20261126115400")
# Only the structure changed: the function's date stays, both type timestamps move.
AFTER_STRUCTURE_CHANGE = _reply("20261126145233", "20261126145233")


def test_the_request_names_the_function_and_every_type_it_uses() -> None:
    params = _metadata_get_params("Z_SAPRFCLIB_DEEP", _desc())
    assert params["FUNCTIONNAMES"] == [{"FUNCTIONNAME": "Z_SAPRFCLIB_DEEP"}]
    assert params["DATATYPES"] == [{"TABNAME": "ZSAPRFCLIB_DEEP"}, {"TABNAME": "ZSAPRFCLIB_FLAT"}]
    assert params["GET_TIMESTAMPS"] == "X"
    assert _descriptor_type_names(_desc()) == ["ZSAPRFCLIB_DEEP", "ZSAPRFCLIB_FLAT"]


def test_a_structure_change_moves_the_stamp_though_the_function_date_does_not() -> None:
    before, after = _metadata_stamp(BEFORE), _metadata_stamp(AFTER_STRUCTURE_CHANGE)
    assert before is not None and after is not None
    assert before[:2] == after[:2]  # UDAT/UTIME unchanged
    assert before != after


def test_a_function_that_is_gone_has_no_stamp() -> None:
    gone = {"FUNCTIONNAMES": [], "FUNC_ERRORS": [{"FUNCNAME": "Z_X", "EXCEPTION": "FU_NOT_FOUND"}]}
    assert _metadata_stamp(gone) is None


def _conn(replies: list[dict[str, Any]]) -> Connection:
    conn = Connection(MockTransport(_handshake_responses()), metadata_cache=MetadataCache())
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    key = conn._metadata_cache_key
    assert key
    conn._cache.put(key, _desc())
    queue = list(replies)

    def call(name: str, **params: Any) -> dict[str, Any]:
        assert name == "RFC_METADATA_GET"
        return queue.pop(0)

    conn.call = call  # type: ignore[method-assign]
    return conn


def test_the_first_check_records_and_a_later_one_finds_the_change() -> None:
    conn = _conn([BEFORE, BEFORE, AFTER_STRUCTURE_CHANGE, AFTER_STRUCTURE_CHANGE])
    key = conn._metadata_cache_key
    assert key
    assert conn.check_metadata() == []  # records the stamp
    assert conn.check_metadata() == []  # nothing moved
    generation = conn._cache.generation
    assert conn.check_metadata() == ["Z_SAPRFCLIB_DEEP"]
    assert conn._cache.get(key, "Z_SAPRFCLIB_DEEP") is None
    assert conn._cache.generation != generation
    # The new stamp is kept: the refetched interface is the current one.
    conn._cache.put(key, _desc())
    assert conn.check_metadata() == []


def test_a_function_that_disappeared_is_invalidated() -> None:
    conn = _conn([BEFORE, {"FUNCTIONNAMES": [], "FUNC_ERRORS": [{"EXCEPTION": "FU_NOT_FOUND"}]}])
    assert conn.check_metadata() == []
    assert conn.check_metadata() == ["Z_SAPRFCLIB_DEEP"]


# --------------------------------------------------------------------------- #
# Pools
# --------------------------------------------------------------------------- #


class _Conn:
    def __init__(self, pool: Any) -> None:
        self.pool = pool
        self.checks = 0
        self.resets = 0
        self.changed: list[str] = []

    def check_metadata(self) -> list[str]:
        self.checks += 1
        if self.changed:
            self.pool._metadata_cache.invalidate(self.changed[0])
        return list(self.changed)

    def ping(self) -> bool:
        return True

    def reset_server_context(self) -> None:
        self.resets += 1

    def close(self) -> None:
        pass


class _Pool(ConnectionPool):
    def _open(self) -> Any:
        return _Conn(self)


def test_a_pool_checks_at_most_once_per_interval_and_resets_on_a_change() -> None:
    pool = _Pool({}, min_size=0, max_size=1, metadata_check_interval=60.0)
    with pool.acquire() as conn:
        pass
    pool._last_check -= 61  # the interval has passed
    conn.changed = ["Z_SAPRFCLIB_DEEP"]
    with pool.acquire():
        pass
    assert (conn.checks, conn.resets) == (1, 1)
    conn.changed = []
    with pool.acquire():
        pass
    assert conn.checks == 1  # not due again yet


def test_a_pool_without_an_interval_never_checks() -> None:
    pool = _Pool({}, min_size=0, max_size=1)
    with pool.acquire() as conn:
        pass
    pool._last_check -= 10_000
    with pool.acquire():
        pass
    assert conn.checks == 0


@pytest.mark.parametrize("bad", [0, -1.0])
def test_the_interval_must_be_positive(bad: float) -> None:
    with pytest.raises(ValueError, match="metadata_check_interval"):
        ConnectionPool({}, min_size=0, metadata_check_interval=bad)
