# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""A call's arguments are copied and bounded before anything is encoded (#86).

Values used to be encoded straight from the caller's objects. A buffered unit kept a
shallow copy, so a row changed after ``unit.call(...)`` changed what was sent; a
generator of rows could be consumed by the first check that walked it; and nothing
bounded the size of what a caller could hand over. ``snapshot_params`` copies the
arguments once, at the start of the call, refuses what cannot be encoded, and
applies the caller's :class:`~saprfclib.CallLimits`.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib import CallLimits, CallParameterError
from saprfclib.codec import RFCTYPE_CHAR, RFCTYPE_TABLE
from saprfclib.connection import Connection
from saprfclib.invoke import _MAX_VALUE_DEPTH, build_invoke_request, snapshot_params
from saprfclib.types import RFC_TABLES, FieldDesc, FunctionDesc, TypeDesc

from ._mocks import MockTransport
from .test_connection import _handshake_responses

# --------------------------------------------------------------------------- #
# Copying
# --------------------------------------------------------------------------- #

leaves = st.one_of(
    st.none(), st.booleans(), st.integers(), st.text(max_size=8), st.binary(max_size=8)
)
values = st.recursive(
    leaves,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4), st.dictionaries(st.text(max_size=4), inner, max_size=4)
    ),
    max_leaves=30,
)


def _containers(value: Any) -> list[int]:
    if isinstance(value, dict):
        return [id(value)] + [i for v in value.values() for i in _containers(v)]
    if isinstance(value, list):
        return [id(value)] + [i for v in value for i in _containers(v)]
    return []


@given(st.dictionaries(st.text(min_size=1, max_size=6), values, max_size=5))
def test_a_snapshot_is_equal_to_the_arguments_and_shares_no_container_with_them(
    params: dict[str, Any],
) -> None:
    copy = snapshot_params(params)
    assert copy == params
    assert not set(_containers(copy)) & set(_containers(params))


def test_changing_the_arguments_afterwards_does_not_change_the_snapshot() -> None:
    row = {"F": "original"}
    params = {"IT": [row], "IS": {"F": bytearray(b"ab")}}
    copy = snapshot_params(params)
    row["F"] = "changed"
    params["IT"].append({"F": "added"})
    params["IS"]["F"][0] = 0
    assert copy == {"IT": [{"F": "original"}], "IS": {"F": b"ab"}}


def test_tuples_and_iterators_become_lists() -> None:
    copy = snapshot_params({"A": ({"F": 1},), "B": ({"F": i} for i in range(3))})
    assert copy == {"A": [{"F": 1}], "B": [{"F": 0}, {"F": 1}, {"F": 2}]}


def test_immutable_values_are_kept_as_they_are() -> None:
    import datetime
    from decimal import Decimal

    day = datetime.date(2026, 11, 26)
    amount = Decimal("1.05")
    copy = snapshot_params({"D": day, "P": amount})
    assert copy["D"] is day and copy["P"] is amount


# --------------------------------------------------------------------------- #
# What is refused, and where it is named
# --------------------------------------------------------------------------- #


def test_a_value_that_contains_itself_is_refused_with_its_path() -> None:
    row: dict[str, Any] = {"F": "x"}
    row["SELF"] = [row]
    with pytest.raises(CallParameterError) as info:
        snapshot_params({"IT": [row]})
    assert info.value.path == "IT[0]-SELF[0]"
    assert isinstance(info.value, ValueError)


def test_the_same_object_twice_is_not_a_cycle() -> None:
    shared = {"F": "x"}
    assert snapshot_params({"IT": [shared, shared]}) == {"IT": [shared, shared]}


def test_nesting_deeper_than_any_interface_is_refused() -> None:
    value: Any = "leaf"
    for _ in range(_MAX_VALUE_DEPTH):
        value = [value]
    snapshot_params({"P": value})  # exactly at the bound
    with pytest.raises(CallParameterError, match="nested deeper") as info:
        snapshot_params({"P": [value]})
    assert info.value.path.startswith("P")


@given(rows=st.integers(min_value=0, max_value=20), limit=st.integers(min_value=0, max_value=20))
def test_max_table_rows_refuses_exactly_the_tables_longer_than_it(rows: int, limit: int) -> None:
    params = {"IT": [{"F": i} for i in range(rows)]}
    if rows > limit:
        with pytest.raises(CallParameterError) as info:
            snapshot_params(params, CallLimits(max_table_rows=limit))
        assert info.value.path == "IT"
    else:
        assert snapshot_params(params, CallLimits(max_table_rows=limit)) == params


def test_max_table_rows_stops_reading_an_endless_iterator() -> None:
    def endless() -> Any:
        while True:
            yield {"F": "x"}

    with pytest.raises(CallParameterError, match="max_table_rows=1000"):
        snapshot_params({"IT": endless()}, CallLimits(max_table_rows=1000))


def test_max_table_rows_applies_to_nested_tables() -> None:
    with pytest.raises(CallParameterError) as info:
        snapshot_params({"IS": {"T": [1, 2, 3]}}, CallLimits(max_table_rows=2))
    assert info.value.path == "IS-T"


def test_max_value_bytes_counts_text_as_it_is_sent() -> None:
    # 'a' is one UTF-16 code unit (2 bytes); U+1F600 is a surrogate pair (4 bytes).
    assert snapshot_params({"A": "a\U0001f600"}, CallLimits(max_value_bytes=6))
    with pytest.raises(CallParameterError) as info:
        snapshot_params({"A": "a\U0001f600", "B": b"x"}, CallLimits(max_value_bytes=6))
    assert info.value.path == "B"


def test_the_error_names_the_limit_but_never_the_value() -> None:
    with pytest.raises(CallParameterError) as info:
        snapshot_params({"PW": "s3cret-value"}, CallLimits(max_value_bytes=4))
    assert "s3cret" not in str(info.value)


@pytest.mark.parametrize("bad", [-1, True, 1.5, "10"])
def test_call_limits_refuse_nonsense(bad: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        CallLimits(max_table_rows=bad)
    with pytest.raises((TypeError, ValueError)):
        CallLimits(max_value_bytes=bad)


# --------------------------------------------------------------------------- #
# Through a connection
# --------------------------------------------------------------------------- #


def _row_type() -> TypeDesc:
    return TypeDesc(
        name="ZROW",
        fields=[
            FieldDesc(
                name="F",
                rfctype=RFCTYPE_CHAR,
                nuc_length=4,
                nuc_offset=0,
                uc_length=8,
                uc_offset=0,
                decimals=0,
            )
        ],
        nuc_size=4,
        uc_size=8,
    )


def _desc() -> FunctionDesc:
    return FunctionDesc(
        name="Z_FM_A",
        parameters=[
            FieldDesc(
                name="IT",
                rfctype=RFCTYPE_TABLE,
                nuc_length=4,
                nuc_offset=0,
                uc_length=8,
                uc_offset=0,
                decimals=0,
                type_desc=_row_type(),
                direction=RFC_TABLES,
            )
        ],
    )


def _conn(**kwargs: Any) -> tuple[Connection, MockTransport]:
    transport = MockTransport(_handshake_responses())
    conn = Connection(transport, **kwargs)
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    key = conn._metadata_cache_key
    assert key
    conn._cache.put(key, _desc())
    return conn, transport


def test_a_generator_of_rows_is_sent_in_full() -> None:
    conn, transport = _conn()
    sent_before = len(transport.sent)
    with pytest.raises(Exception):  # noqa: B017 — no reply is scripted; only the request matters
        conn.call("Z_FM_A", IT=({"F": f"R{i}"} for i in range(3)))
    request = transport.sent[sent_before]
    expected = build_invoke_request("Z_FM_A", _desc(), {"IT": [{"F": f"R{i}"} for i in range(3)]})
    assert expected[20:] in request, "all three rows, encoded as a list would be"


def test_a_call_over_its_limit_sends_nothing() -> None:
    conn, transport = _conn(call_limits=CallLimits(max_table_rows=2))
    sent_before = len(transport.sent)
    with pytest.raises(CallParameterError):
        conn.call("Z_FM_A", IT=[{"F": "a"}] * 3)
    assert len(transport.sent) == sent_before
    # Refused before the call started, so the connection is still usable.
    assert conn._session.state.name == "READY"


def test_a_buffered_unit_call_is_not_changed_by_later_edits() -> None:
    conn, _ = _conn()
    unit = conn.create_unit()
    row = {"F": "orig"}
    unit.call("Z_FM_A", IT=[row])
    row["F"] = "edit"
    assert unit._buffered[0][1] == {"IT": [{"F": "orig"}]}


def test_a_buffered_unit_call_honours_the_connection_limits() -> None:
    conn, _ = _conn(call_limits=CallLimits(max_table_rows=1))
    unit = conn.create_unit()
    with pytest.raises(CallParameterError):
        unit.call("Z_FM_A", IT=[{"F": "a"}, {"F": "b"}])
