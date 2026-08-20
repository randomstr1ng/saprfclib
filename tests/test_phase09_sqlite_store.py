# tests/test_phase09_sqlite_store.py
#
# Phase 9 RED→GREEN tests: SqliteTidStore / SqliteUnitStore (TRFC-08).
#
# These tests encode the full D-04 / D-05 / D-03b / T-09-02-SQLI contract
# for both durable stores. All tests skip cleanly until SqliteTidStore and
# SqliteUnitStore are present in saprfclib.stores (Plan 09-02 lands them).
#
# Coverage: TRFC-08 (pluggable durable stores)
#
# Acceptance criteria encoded:
#   - :memory: round-trip mark_received / mark_executed / is_executed
#   - :memory: persistence across many ops on ONE instance (Pitfall 5)
#   - On-disk restart durability (one instance writes, second reopens + reads)
#   - park(tid, payload) / get_parked(tid) / list_parked() (D-03b)
#   - Parameterized-key SQL injection attempt (T-06-S01 / TRFC-08 security)
#   - user_version migration idempotence (D-05 / Pitfall 3)
#   - SqliteUnitStore round-trip + UnitState assertions

from __future__ import annotations

import pytest

saprfc_stores = pytest.importorskip(
    "saprfclib.stores",
    reason="saprfclib.stores not importable — skipping Phase 9 SQLite store tests",
)

# Guard on absent production symbols.
SqliteTidStore = getattr(saprfc_stores, "SqliteTidStore", None)
SqliteUnitStore = getattr(saprfc_stores, "SqliteUnitStore", None)

_SKIP_TID = pytest.mark.skipif(
    SqliteTidStore is None,
    reason="SqliteTidStore not yet in saprfclib.stores (09-02 not landed)",
)
_SKIP_UNIT = pytest.mark.skipif(
    SqliteUnitStore is None,
    reason="SqliteUnitStore not yet in saprfclib.stores (09-02 not landed)",
)

# UnitState is present (Phase 6); used in UnitStore assertions.
from saprfclib.stores import UnitState  # noqa: E402

# --------------------------------------------------------------------------- #
# SqliteTidStore — :memory: round-trip
# --------------------------------------------------------------------------- #


@_SKIP_TID
def test_sqlite_tid_store_round_trip() -> None:
    """TRFC-08: mark_received → mark_executed → is_executed round-trip on :memory:.

    Verifies the basic TID lifecycle:
    1. is_executed(tid) is False before any mark_*.
    2. mark_received(tid) sets state to 'received'; is_executed still False.
    3. mark_executed(tid) sets state to 'executed'; is_executed returns True.
    4. confirm(tid) cleans up; is_executed returns False again.
    """
    store = SqliteTidStore(":memory:")
    tid = "SQLITEST0000000000000001"  # 24 chars

    assert not store.is_executed(tid), "New TID must not be executed"

    store.mark_received(tid)
    assert not store.is_executed(tid), "After mark_received: is_executed still False"

    store.mark_executed(tid)
    assert store.is_executed(tid), "After mark_executed: is_executed must be True"

    store.confirm(tid)
    assert not store.is_executed(tid), "After confirm: is_executed must be False"

    store.close()


@_SKIP_TID
def test_sqlite_tid_store_rolled_back() -> None:
    """TRFC-08: mark_rolled_back leaves is_executed as False.

    A rolled-back TID must not be treated as executed — the backend may
    re-send the same TID, and it must be executed again.
    """
    store = SqliteTidStore(":memory:")
    tid = "SQLIRB000000000000000001"  # 24 chars

    store.mark_received(tid)
    store.mark_rolled_back(tid)
    assert not store.is_executed(tid), "Rolled-back TID must not be is_executed=True"

    store.close()


@_SKIP_TID
def test_sqlite_tid_store_memory_persistence() -> None:
    """TRFC-08 / Pitfall 5: :memory: store retains state across many operations.

    One SqliteTidStore(":memory:") instance must share a single connection so
    writes are visible on subsequent reads. (Each :memory: connection is a
    separate DB — this test catches the Pitfall 5 bug.)

    Writes 100 TIDs, then reads them all back; all must be found.
    """
    store = SqliteTidStore(":memory:")
    n = 100
    tids = [f"PERSIST{i:017d}"[:24] for i in range(n)]

    for tid in tids:
        store.mark_executed(tid)

    for tid in tids:
        assert store.is_executed(tid), (
            f"TID {tid!r} not found — Pitfall 5: :memory: connection-per-call "
            "creates a separate DB, losing all state"
        )

    store.close()


@_SKIP_TID
def test_sqlite_tid_store_disk_durability(tmp_path: pytest.TempPathFactory) -> None:
    """TRFC-08: mark_executed persists across process-restart (on-disk DB).

    Opens SqliteTidStore at tmp_path / "tids.db", marks a TID executed, closes.
    Opens a SECOND SqliteTidStore at the same path; is_executed returns True.

    Verifies durable persistence beyond process lifetime — the core value of
    SqliteTidStore over InMemoryTidStore.
    """
    db_path = str(tmp_path / "tids.db")
    tid = "DURABLE0000000000000000T"  # 24 chars

    store1 = SqliteTidStore(db_path)
    store1.mark_executed(tid)
    store1.close()

    store2 = SqliteTidStore(db_path)
    assert store2.is_executed(tid), (
        "After closing and reopening, is_executed must still be True (durable DB)"
    )
    store2.close()


# --------------------------------------------------------------------------- #
# SqliteTidStore — park / get_parked / list_parked (D-03b payload column)
# --------------------------------------------------------------------------- #


@_SKIP_TID
def test_sqlite_tid_store_park_and_get_parked() -> None:
    """TRFC-08 / D-03b: park(tid, payload) stores bytes; get_parked returns exact bytes.

    After park(tid, b"payload"), get_parked(tid) must return the exact same
    bytes. This enables conn.retry_parked(tid) re-drive without re-marshaling.
    """
    store = SqliteTidStore(":memory:")
    tid = "PARKTEST00000000000000D1"  # 24 chars

    # Unknown tid: None
    assert store.get_parked(tid) is None

    payload = b"\x00\x01\x02serialized-payload"
    store.park(tid, payload)
    assert store.get_parked(tid) == payload, "get_parked must return exact bytes after park"

    store.close()


@_SKIP_TID
def test_sqlite_tid_store_list_parked() -> None:
    """TRFC-08 / D-03b: list_parked() includes TIDs whose payloads were parked.

    After park(tid, payload), list_parked() must include the tid. After
    confirm(tid), the tid must no longer appear in list_parked().
    """
    store = SqliteTidStore(":memory:")
    tid = "PARKTEST00000000000000D2"  # 24 chars

    store.park(tid, b"payload-bytes")
    assert tid in store.list_parked(), "Parked TID must appear in list_parked()"

    store.confirm(tid)
    assert tid not in store.list_parked(), "After confirm, TID must not appear in list_parked()"

    store.close()


# --------------------------------------------------------------------------- #
# SqliteTidStore — SQL injection safety (T-06-S01 / TRFC-08 security)
# --------------------------------------------------------------------------- #


@_SKIP_TID
def test_sqlite_tid_store_parameterized_key_injection() -> None:
    """TRFC-08 / T-06-S01: injection attempt via tid is stored/queried without error.

    The TID "X'; DROP TABLE tids;--" is peer-influenced untrusted input. The
    store must use parameterised queries so this value is stored and retrieved
    correctly WITHOUT causing a SQL error or dropping any table.

    Asserts:
    - mark_received(injection_tid) does not raise.
    - mark_executed(injection_tid) does not raise.
    - is_executed(injection_tid) returns True.
    - A subsequent mark_received on a normal tid succeeds (table was not dropped).
    """
    store = SqliteTidStore(":memory:")
    injection_tid = "X'; DROP TABLE tids;--"  # 22 chars (< 24 is still valid for test)

    store.mark_received(injection_tid)
    store.mark_executed(injection_tid)
    assert store.is_executed(injection_tid), (
        "Injection TID must be stored and queried correctly (parameterized)"
    )

    # If DROP TABLE succeeded, this would raise or return wrong result
    normal_tid = "NORMAL00000000000000000N"  # 24 chars
    store.mark_received(normal_tid)
    assert not store.is_executed(normal_tid), (
        "Normal TID after injection attempt — table must still exist"
    )

    store.close()


# --------------------------------------------------------------------------- #
# SqliteTidStore — user_version migration idempotence (D-05 / Pitfall 3)
# --------------------------------------------------------------------------- #


@_SKIP_TID
def test_sqlite_tid_store_migration_idempotence(tmp_path: pytest.TempPathFactory) -> None:
    """TRFC-08 / D-05: constructing SqliteTidStore twice on the same DB does not raise.

    Auto-migration uses CREATE TABLE IF NOT EXISTS + PRAGMA user_version (not
    ALTER TABLE ADD COLUMN IF NOT EXISTS, which is invalid SQLite — Pitfall 3).
    Constructing the store a second time on an existing DB must be a no-op.

    Asserts:
    - First construction: no error.
    - Second construction (same path): no error.
    - PRAGMA user_version == expected schema version (>= 1).
    """
    import sqlite3

    db_path = str(tmp_path / "migrate.db")

    store1 = SqliteTidStore(db_path)
    store1.close()

    # Second construction on existing DB must not raise
    store2 = SqliteTidStore(db_path)

    # Verify schema version >= 1
    conn = sqlite3.connect(db_path)
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()
    assert ver >= 1, f"PRAGMA user_version must be >= 1 after migration; got {ver}"

    store2.close()


# --------------------------------------------------------------------------- #
# SqliteUnitStore — round-trip + UnitState assertions (TRFC-08)
# --------------------------------------------------------------------------- #


@_SKIP_UNIT
def test_sqlite_unit_store_round_trip() -> None:
    """TRFC-08: SqliteUnitStore persist/confirm/get_unit_state round-trip on :memory:.

    Verifies the basic Unit lifecycle:
    1. get_unit_state(uid, type) returns UnitState.NOT_FOUND before persist.
    2. persist(uid, type) sets state to UnitState.IN_PROCESS.
    3. confirm(uid, type) sets state to UnitState.CONFIRMED.
    4. get_unit_state after confirm returns CONFIRMED (or NOT_FOUND if cleaned up).
    """
    store = SqliteUnitStore(":memory:")
    uid = "A" * 32
    utype = "T"

    state = store.get_unit_state(uid, utype)
    assert state is UnitState.NOT_FOUND, f"Unknown unit must return NOT_FOUND; got {state!r}"

    store.persist(uid, utype)
    state = store.get_unit_state(uid, utype)
    assert state is UnitState.IN_PROCESS, f"After persist, state must be IN_PROCESS; got {state!r}"

    store.confirm(uid, utype)
    state = store.get_unit_state(uid, utype)
    assert state in (UnitState.CONFIRMED, UnitState.NOT_FOUND), (
        f"After confirm, state must be CONFIRMED or NOT_FOUND; got {state!r}"
    )

    store.close()


@_SKIP_UNIT
def test_sqlite_unit_store_unit_type_isolation() -> None:
    """TRFC-08: 'T' and 'Q' unit types for the same unit_id are tracked separately.

    Pitfall 5 (from Phase 6): the same unit_id may coexist with different
    unit_types. They must be keyed on (unit_id, unit_type) separately.

    Asserts:
    - persist(uid, 'T') does not affect get_unit_state(uid, 'Q').
    - persist(uid, 'Q') does not affect get_unit_state(uid, 'T').
    """
    store = SqliteUnitStore(":memory:")
    uid = "B" * 32

    store.persist(uid, "T")
    assert store.get_unit_state(uid, "Q") is UnitState.NOT_FOUND, (
        "persist('T') must not affect state for 'Q' unit type"
    )

    store.persist(uid, "Q")
    # 'T' state should still be IN_PROCESS (not changed by persist('Q'))
    assert store.get_unit_state(uid, "T") is UnitState.IN_PROCESS, (
        "persist('Q') must not affect state for 'T' unit type"
    )

    store.close()


@_SKIP_UNIT
def test_sqlite_unit_store_disk_durability(tmp_path: pytest.TempPathFactory) -> None:
    """TRFC-08: SqliteUnitStore persist state survives process restart (on-disk DB).

    Opens a SqliteUnitStore, persists a unit, closes. Opens a second instance
    at the same path; get_unit_state returns IN_PROCESS (or COMMITTED/CONFIRMED).

    Verifies durable Unit tracking beyond process lifetime.
    """
    db_path = str(tmp_path / "units.db")
    uid = "C" * 32
    utype = "T"

    store1 = SqliteUnitStore(db_path)
    store1.persist(uid, utype)
    store1.close()

    store2 = SqliteUnitStore(db_path)
    state = store2.get_unit_state(uid, utype)
    assert state in (UnitState.IN_PROCESS, UnitState.COMMITTED, UnitState.CONFIRMED), (
        f"Persisted unit state must survive DB reopen; got {state!r}"
    )
    store2.close()
