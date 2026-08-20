# tests/test_phase06_stores.py
#
# Phase 6 — TidStore / UnitStore Protocol conformance tests (TRFC-08).
#
# Wave 0 status: RED scaffold — saprfclib.stores does not exist until Plan 06-02.
# Uses pytest.importorskip("saprfclib.stores") so the file is collectable and skips
# cleanly when the module is absent. No xfail needed: importorskip is the correct
# RED mechanism for "whole module missing" cases (plan specifies importorskip).
#
# Requirement coverage:
#   TRFC-08: TidStore / UnitStore Protocol interfaces + InMemory defaults
#            satisfy all Protocol structural requirements; isinstance() confirms
#            @runtime_checkable; InMemoryTidStore is thread-safe under concurrent
#            check/mark_received/mark_executed calls.
#
# Sources: 06-CONTEXT.md D-01/02/03; 06-RESEARCH.md Pattern 1 (Protocol shape);
#          the SDK's RFC_UNIT_STATE enum (5 values);
#          docs/protocol/trfc.md §"TID / UnitID Validation"

from __future__ import annotations

import threading

import pytest

# RED gate: saprfclib.stores is created in Plan 06-02.
# The ENTIRE module body runs only when the import succeeds.
stores = pytest.importorskip("saprfclib.stores")


# --------------------------------------------------------------------------- #
# Symbols this test depends on (collected after importorskip succeeds)
# --------------------------------------------------------------------------- #

TidStore = stores.TidStore
UnitStore = stores.UnitStore
UnitState = stores.UnitState
InMemoryTidStore = stores.InMemoryTidStore
InMemoryUnitStore = stores.InMemoryUnitStore


# --------------------------------------------------------------------------- #
# UnitState enum shape (TRFC-08, SDK type definitions-332)
# --------------------------------------------------------------------------- #


def test_unit_state_enum_has_all_five_values() -> None:
    """UnitState enum must expose all 5 values from the SDK's RFC_UNIT_STATE.

    NOT_FOUND=0, IN_PROCESS=1, COMMITTED=2, ROLLED_BACK=3, CONFIRMED=4
    """
    required = {"NOT_FOUND", "IN_PROCESS", "COMMITTED", "ROLLED_BACK", "CONFIRMED"}
    actual = {m.name for m in UnitState}
    assert required <= actual, (
        f"UnitState missing members: {required - actual} "
        f"(must mirror the SDK's RFC_UNIT_STATE values)"
    )


# --------------------------------------------------------------------------- #
# Protocol conformance: isinstance via @runtime_checkable (D-01)
# --------------------------------------------------------------------------- #


def test_protocol_conformance() -> None:
    """InMemoryTidStore and InMemoryUnitStore satisfy their Protocol contracts.

    Verifies @runtime_checkable isinstance checks pass (D-01), and that all
    required methods exist (structural typing, no ABC inheritance).
    Checks:
    - TidStore: is_executed, mark_received, mark_executed, mark_rolled_back, confirm
    - UnitStore: get_unit_state, persist, confirm
    """
    tid_store = InMemoryTidStore()
    unit_store = InMemoryUnitStore()

    # @runtime_checkable isinstance check (D-01)
    assert isinstance(tid_store, TidStore), (
        "InMemoryTidStore must satisfy TidStore Protocol (isinstance check, D-01)"
    )
    assert isinstance(unit_store, UnitStore), (
        "InMemoryUnitStore must satisfy UnitStore Protocol (isinstance check, D-01)"
    )

    # TidStore structural methods
    for method in ("is_executed", "mark_received", "mark_executed", "mark_rolled_back", "confirm"):
        assert callable(getattr(tid_store, method, None)), (
            f"TidStore must have callable method {method!r} (D-02 Protocol shape)"
        )

    # UnitStore structural methods
    for method in ("get_unit_state", "persist", "confirm"):
        assert callable(getattr(unit_store, method, None)), (
            f"UnitStore must have callable method {method!r} (D-02 Protocol shape)"
        )


# --------------------------------------------------------------------------- #
# InMemoryTidStore: basic state machine (TRFC-08)
# --------------------------------------------------------------------------- #


def test_inmemory_tid_store_new_tid_not_executed() -> None:
    """A new TID must not be considered executed."""
    store = InMemoryTidStore()
    assert not store.is_executed("TESTTID000000000000000001"), (
        "New TID must not be executed (is_executed returns False before mark_executed)"
    )


def test_inmemory_tid_store_mark_received_then_executed() -> None:
    """mark_received → mark_executed transitions TID through the lifecycle."""
    store = InMemoryTidStore()
    tid = "LIFECYCLE0000000000000000"[:24]
    assert not store.is_executed(tid)
    store.mark_received(tid)
    # After mark_received only: is_executed still False (not yet committed)
    assert not store.is_executed(tid)
    store.mark_executed(tid)
    assert store.is_executed(tid)


def test_inmemory_tid_store_mark_rolled_back() -> None:
    """mark_rolled_back after mark_received: TID persisted but not executed."""
    store = InMemoryTidStore()
    tid = "ROLLBACK000000000000000000"[:24]
    store.mark_received(tid)
    store.mark_rolled_back(tid)
    assert not store.is_executed(tid), "Rolled-back TID must not report is_executed=True"


def test_inmemory_tid_store_confirm_removes_or_clears() -> None:
    """confirm() must not raise; may remove or clear TID from active tracking."""
    store = InMemoryTidStore()
    tid = "CONFIRM0000000000000000000"[:24]
    store.mark_received(tid)
    store.mark_executed(tid)
    store.confirm(tid)  # must not raise


# --------------------------------------------------------------------------- #
# InMemoryTidStore: thread safety (TRFC-08 + SDK type definitions SERVER-06 lineage)
# --------------------------------------------------------------------------- #


def test_inmemory_tid_store_thread_safe_concurrent_mark() -> None:
    """Concurrent mark_received + mark_executed from N threads must not corrupt state.

    Uses threading.Lock-protected InMemoryTidStore (D-13 sync-first pattern).
    50 threads each handle a unique TID to avoid interference.
    """
    store = InMemoryTidStore()
    n_threads = 50
    errors: list[Exception] = []

    def _worker(tid: str) -> None:
        try:
            store.mark_received(tid)
            store.mark_executed(tid)
            assert store.is_executed(tid), f"TID {tid!r} must be executed after mark"
        except Exception as exc:
            errors.append(exc)

    tids = [f"TH{i:022d}"[:24] for i in range(n_threads)]
    threads = [threading.Thread(target=_worker, args=(t,)) for t in tids]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=5.0)

    assert not errors, f"Thread-safety errors in InMemoryTidStore: {errors}"


# --------------------------------------------------------------------------- #
# InMemoryUnitStore: basic contract (TRFC-08)
# --------------------------------------------------------------------------- #


def test_inmemory_unit_store_unknown_unit_returns_not_found() -> None:
    """get_unit_state for an unknown UnitID must return UnitState.NOT_FOUND."""
    store = InMemoryUnitStore()
    state = store.get_unit_state("A" * 32, "T")
    assert state is UnitState.NOT_FOUND, (
        f"Unknown UnitID must return NOT_FOUND (h:327); got {state!r}"
    )


def test_inmemory_unit_store_persist_sets_in_process() -> None:
    """persist() must advance UnitID to at least IN_PROCESS state."""
    import uuid

    store = InMemoryUnitStore()
    uid = uuid.uuid4().hex.upper()
    store.persist(uid, "T")
    state = store.get_unit_state(uid, "T")
    assert state in (UnitState.IN_PROCESS, UnitState.COMMITTED), (
        f"After persist(), state must be IN_PROCESS or COMMITTED; got {state!r}"
    )


def test_inmemory_unit_store_confirm() -> None:
    """confirm() must not raise and must set state to CONFIRMED or allow cleanup."""
    import uuid

    store = InMemoryUnitStore()
    uid = uuid.uuid4().hex.upper()
    store.persist(uid, "Q")
    store.confirm(uid, "Q")  # must not raise

    state = store.get_unit_state(uid, "Q")
    # Either CONFIRMED or NOT_FOUND (if confirm removes the entry) — both are valid
    assert state in (UnitState.CONFIRMED, UnitState.NOT_FOUND), (
        f"After confirm(), state must be CONFIRMED or NOT_FOUND; got {state!r}"
    )


# --------------------------------------------------------------------------- #
# Duck-typed custom store (D-01: no inheritance required)
# --------------------------------------------------------------------------- #


def test_duck_typed_tid_store_satisfies_protocol() -> None:
    """A duck-typed class with the right methods satisfies TidStore without inheriting.

    D-01: Protocol uses structural typing — no ABC inheritance required.
    Includes park/get_parked/list_parked/delete_parked (D-03b extensions).
    """

    class MyStore:
        def is_executed(self, tid: str) -> bool:
            return False

        def mark_received(self, tid: str) -> None:
            pass

        def mark_executed(self, tid: str) -> None:
            pass

        def mark_rolled_back(self, tid: str) -> None:
            pass

        def confirm(self, tid: str) -> None:
            pass

        def park(self, tid: str, payload: bytes) -> None:
            pass

        def get_parked(self, tid: str) -> bytes | None:
            return None

        def list_parked(self) -> list[str]:
            return []

        def delete_parked(self, tid: str) -> None:
            pass

    assert isinstance(MyStore(), TidStore), (
        "Duck-typed class with all TidStore methods must satisfy Protocol (D-01)"
    )


def test_incomplete_duck_typed_class_fails_protocol() -> None:
    """A class missing a required method must NOT satisfy TidStore Protocol."""

    class IncompleteStore:
        def is_executed(self, tid: str) -> bool:
            return False

        # missing: mark_received, mark_executed, mark_rolled_back, confirm

    assert not isinstance(IncompleteStore(), TidStore), (
        "Incomplete duck-typed class must NOT satisfy TidStore (@runtime_checkable)"
    )


# --------------------------------------------------------------------------- #
# InMemoryTidStore: park/get_parked/list_parked/delete_parked (D-03b)
# --------------------------------------------------------------------------- #


def test_inmemory_tid_store_park_round_trip() -> None:
    """park(tid, payload) then get_parked(tid) returns exact bytes (D-03b).

    Enables conn.retry_parked(tid) re-drive without re-marshaling.
    """
    store = InMemoryTidStore()
    tid = "PARKTEST00000000000000C1"  # exactly 24 chars

    # Before park: unknown tid returns None
    assert store.get_parked(tid) is None

    # After park: exact bytes returned
    payload = b"serialized-request-bytes"
    store.park(tid, payload)
    assert store.get_parked(tid) == payload

    # Parking stores a copy (mutation of original must not alter stored bytes)
    mutable = bytearray(b"mutable")
    store.park(tid, mutable)
    mutable[0] = ord("X")
    assert store.get_parked(tid) == b"mutable"


def test_inmemory_tid_store_park_list_and_delete() -> None:
    """list_parked() reflects parked TIDs; delete_parked removes them (D-03b)."""
    store = InMemoryTidStore()
    tid1 = "PARKTEST00000000000000A1"  # exactly 24 chars
    tid2 = "PARKTEST00000000000000A2"  # exactly 24 chars

    store.park(tid1, b"payload1")
    store.park(tid2, b"payload2")

    parked = store.list_parked()
    assert tid1 in parked
    assert tid2 in parked

    store.delete_parked(tid1)
    assert store.get_parked(tid1) is None
    assert tid1 not in store.list_parked()
    # tid2 still present
    assert tid2 in store.list_parked()


def test_inmemory_tid_store_park_does_not_affect_state() -> None:
    """Parking a payload does NOT change is_executed() result (D-03b)."""
    store = InMemoryTidStore()
    tid = "PARKTEST00000000000000B1"  # exactly 24 chars — already executed
    store.mark_executed(tid)
    assert store.is_executed(tid)
    store.park(tid, b"some-payload")
    # is_executed still True after parking
    assert store.is_executed(tid)
    # not-yet-executed TID stays False after being parked
    tid2 = "PARKTEST00000000000000B2"  # exactly 24 chars — not executed
    store.park(tid2, b"new-payload")
    assert not store.is_executed(tid2)


# --------------------------------------------------------------------------- #
# InMemoryUnitStore: park/get_parked/list_parked/delete_parked (D-03b)
# --------------------------------------------------------------------------- #


def test_inmemory_unit_store_park_round_trip() -> None:
    """park(uid, utype, payload) then get_parked returns exact bytes (D-03b)."""
    store = InMemoryUnitStore()
    uid = "A" * 32
    utype = "T"

    assert store.get_parked(uid, utype) is None

    payload = b"unit-payload-bytes"
    store.park(uid, utype, payload)
    assert store.get_parked(uid, utype) == payload


def test_inmemory_unit_store_park_list_and_delete() -> None:
    """list_parked() and delete_parked() work for UnitStore (D-03b)."""
    store = InMemoryUnitStore()
    uid = "B" * 32

    store.park(uid, "T", b"t-payload")
    store.park(uid, "Q", b"q-payload")

    parked = store.list_parked()
    assert (uid, "T") in parked
    assert (uid, "Q") in parked

    store.delete_parked(uid, "T")
    assert store.get_parked(uid, "T") is None
    assert (uid, "T") not in store.list_parked()
    # Q still present
    assert (uid, "Q") in store.list_parked()
