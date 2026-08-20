# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — Transactional RFC durable-store surface (TRFC-08).
#
# This module provides the pluggable durability seam for tRFC/qRFC/bgRFC:
#
#   TidStore       (D-01)  — structural Protocol for TID duplicate-execution guards.
#   UnitStore      (D-02)  — structural Protocol for bgRFC Unit lifecycle tracking.
#   UnitState      (RFC_UNIT_STATE, SDK type definitions-332) — five-value enum.
#   InMemoryTidStore  (D-03) — process-lifetime default, thread-safe.
#   InMemoryUnitStore (D-03) — process-lifetime default, thread-safe.
#   SqliteTidStore    (D-04) — durable stdlib sqlite3 TID store, :memory:-safe.
#   SqliteUnitStore   (D-04) — durable stdlib sqlite3 Unit store, :memory:-safe.
#   AsyncTidStore     (D-08) — @runtime_checkable async Protocol (structural only).
#   AsyncUnitStore    (D-08) — @runtime_checkable async Protocol (structural only).
#   _SCHEMA_VERSION          — integer schema version for PRAGMA user_version migration.
#
# Both sync Protocols use @runtime_checkable so ``isinstance(obj, TidStore)`` works
# with duck-typed objects (no inheritance required — structural typing, D-01).
#
# Security (T-06-S01 / RESEARCH V5 / T-09-02-SQLI):
#   TID keys are peer-influenced strings (24 chars from the RFC_UNIT_IDENTIFIER
#   alphabet) and UnitID keys are peer-influenced 32-char uppercase-hex strings.
#   The Protocol docstrings document the untrusted-key contract; store implementers
#   MUST treat these keys as untrusted: use parameterised queries (? placeholders),
#   never concatenate into SQL or file paths.  InMemory stores use them only as
#   Python dict keys (safe).  Sqlite stores use only parameterised queries
#   (enforced by acceptance grep: no f-string/`%`/`.format` in execute calls).
#
# Concurrency (T-06-S03):
#   InMemory* and Sqlite* stores guard writes with a single ``threading.Lock``.
#   Sqlite stores open ONE persistent connection per instance (check_same_thread=False
#   + threading.Lock — Pitfall 5: each :memory: connection is a separate DB, so
#   reconnecting per call would silently drop all data).
#
# Durability:
#   D-03 InMemory* stores are NOT durable — data is lost on process restart.
#   D-04 Sqlite* stores are durable; pass a file path to SqliteTidStore/
#   SqliteUnitStore for persistence across restarts. Use ":memory:" for test
#   isolation.  Caller is responsible for placing the DB file at a secure path
#   (not world-writable) — T-09-02-DISK is accepted, caller responsibility.
#
# Migration (D-05 / Pitfall 3):
#   Sqlite* stores auto-migrate on first open via PRAGMA user_version.  Column
#   adds are NOT guarded with ALTER TABLE … IF NOT EXISTS (invalid in SQLite);
#   future columns must gate on a user_version bump instead.
#
# Async Protocols (D-08):
#   AsyncTidStore / AsyncUnitStore are @runtime_checkable structural Protocols
#   with every method as ``async def``.  No concrete async implementation ships
#   here — the sync Sqlite* stores run under asyncio.to_thread in 09-04.

from __future__ import annotations

__all__ = [
    "TidStore",
    "UnitStore",
    "UnitState",
    "InMemoryTidStore",
    "InMemoryUnitStore",
    "SqliteTidStore",
    "SqliteUnitStore",
    "AsyncTidStore",
    "AsyncUnitStore",
    "_SCHEMA_VERSION",
]

import enum
import sqlite3
import threading
from typing import Protocol, runtime_checkable

# Schema version for PRAGMA user_version migration (D-05 / Pitfall 3).
# Increment when adding new columns; gate on this value in _migrate().
_SCHEMA_VERSION = 1

# --------------------------------------------------------------------------- #
# UnitState enum (RFC_UNIT_STATE, SDK type definitions-332)
# --------------------------------------------------------------------------- #


class UnitState(enum.Enum):
    """Processing state of a bgRFC Unit on the receiver side (RFC_UNIT_STATE).

    Maps the five values from ``RFC_UNIT_STATE`` in SDK type definitions-332. The
    string values mirror the ``ServerSessionState`` style used elsewhere in
    this package (consistent string-valued enum.Enum pattern).

    Values
    ------
    NOT_FOUND  (0)
        No information for this unit in the target system. The send may have
        not reached the target; re-send is appropriate unless ``CONFIRMED``
        was already seen.
    IN_PROCESS (1)
        Backend is persisting (type 'Q') or executing (type 'T') the payload.
        Wait and poll again.
    COMMITTED  (2)
        Data persisted (or executed) on the receiver. Confirm event may be sent.
    ROLLED_BACK (3)
        An error occurred; unit must be re-sent.
    CONFIRMED  (4)
        Temporary state after Confirm and before status erasure. No action needed;
        delete payload and status information on the sender side.
    """

    NOT_FOUND = "NOT_FOUND"
    IN_PROCESS = "IN_PROCESS"
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    CONFIRMED = "CONFIRMED"


# --------------------------------------------------------------------------- #
# TidStore Protocol (D-01 / D-02)
# --------------------------------------------------------------------------- #


@runtime_checkable
class TidStore(Protocol):
    """Structural Protocol for tRFC/qRFC TID duplicate-execution guards (D-01).

    Implementers provide a durable backend (database, Redis, …). Clients
    that implement all five methods satisfy this Protocol without any inheritance
    (structural / duck-typing — D-01 / PEP 544).

    Security contract (T-06-S01)
    -----------------------------
    ``tid`` values are peer-influenced 24-character strings from the RFC TID
    alphabet (``ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_=@-``). Treat ``tid`` as
    **untrusted input**: use parameterised queries; never concatenate ``tid``
    into SQL strings or file paths. Length is expected to be 24 chars
    (``RFC_TID_LN`` in SDK type definitions) but the store MUST NOT silently normalise
    or truncate — document any length enforcement as part of the backend contract.
    """

    def is_executed(self, tid: str) -> bool:
        """Return True if ``tid`` has already been executed (committed)."""
        ...

    def mark_received(self, tid: str) -> None:
        """Record that ``tid`` has been received and is now in-flight."""
        ...

    def mark_executed(self, tid: str) -> None:
        """Record that the function module for ``tid`` executed successfully."""
        ...

    def mark_rolled_back(self, tid: str) -> None:
        """Record that the execution for ``tid`` was rolled back (error path)."""
        ...

    def confirm(self, tid: str) -> None:
        """Confirm ``tid``; may remove or archive it from active tracking."""
        ...

    def park(self, tid: str, payload: bytes) -> None:
        """Store serialised request bytes alongside TID state for later re-drive (D-03b).

        ``bytes(payload)`` copies are stored — caller mutations to the source
        buffer do not affect the stored payload.

        Security contract (T-06-S01): ``tid`` is peer-influenced untrusted input.
        Use parameterised queries; never concatenate ``tid`` into SQL or file paths.
        """
        ...

    def get_parked(self, tid: str) -> bytes | None:
        """Return the parked payload for ``tid``, or ``None`` if not parked (D-03b).

        Security contract (T-06-S01): ``tid`` is peer-influenced untrusted input.
        Use parameterised queries; never concatenate ``tid`` into SQL or file paths.
        """
        ...

    def list_parked(self) -> list[str]:
        """Return a list of TIDs that currently have a non-null parked payload (D-03b)."""
        ...

    def delete_parked(self, tid: str) -> None:
        """Remove the parked payload for ``tid``; get_parked then returns None (D-03b).

        Security contract (T-06-S01): ``tid`` is peer-influenced untrusted input.
        Use parameterised queries; never concatenate ``tid`` into SQL or file paths.
        """
        ...


# --------------------------------------------------------------------------- #
# UnitStore Protocol (D-02)
# --------------------------------------------------------------------------- #


@runtime_checkable
class UnitStore(Protocol):
    """Structural Protocol for bgRFC Unit lifecycle tracking (D-02).

    Keyed on ``(unit_id, unit_type)`` where ``unit_type`` is ``'T'`` (no queues)
    or ``'Q'`` (queues — Pitfall 5 from RESEARCH.md). Implementers must handle
    both unit types; the type is part of the key because the same ``unit_id``
    MUST be tracked separately per type in the bgRFC protocol.

    Security contract (T-06-S01)
    -----------------------------
    ``unit_id`` values are peer-influenced 32-character uppercase hex strings
    (``RFC_UNITID_LN`` in SDK type definitions). Treat as **untrusted input**: use
    parameterised queries; never concatenate into SQL or file paths.
    ``unit_type`` is ``'T'`` or ``'Q'``; validate before use.
    """

    def get_unit_state(self, unit_id: str, unit_type: str) -> UnitState:
        """Return the current :class:`UnitState` for ``(unit_id, unit_type)``.

        Returns ``UnitState.NOT_FOUND`` for unknown units.
        """
        ...

    def persist(self, unit_id: str, unit_type: str) -> None:
        """Persist the Unit; transition state to at least ``IN_PROCESS``."""
        ...

    def confirm(self, unit_id: str, unit_type: str) -> None:
        """Confirm the Unit; transition state to ``CONFIRMED`` or remove entry."""
        ...

    def park(self, unit_id: str, unit_type: str, payload: bytes) -> None:
        """Store serialised request bytes for ``(unit_id, unit_type)`` (D-03b).

        ``bytes(payload)`` copies are stored — caller mutations do not affect
        the stored payload.

        Security contract (T-06-S01): ``unit_id`` / ``unit_type`` are
        peer-influenced untrusted inputs.  Use parameterised queries; never
        concatenate into SQL or file paths.
        """
        ...

    def get_parked(self, unit_id: str, unit_type: str) -> bytes | None:
        """Return the parked payload for ``(unit_id, unit_type)``, or None (D-03b).

        Security contract (T-06-S01): ``unit_id`` / ``unit_type`` are
        peer-influenced untrusted inputs.
        """
        ...

    def list_parked(self) -> list[tuple[str, str]]:
        """Return ``(unit_id, unit_type)`` pairs that have a non-null payload (D-03b)."""
        ...

    def delete_parked(self, unit_id: str, unit_type: str) -> None:
        """Remove the parked payload for ``(unit_id, unit_type)`` (D-03b).

        Security contract (T-06-S01): ``unit_id`` / ``unit_type`` are
        peer-influenced untrusted inputs.
        """
        ...


# --------------------------------------------------------------------------- #
# InMemoryTidStore — process-lifetime default (D-03)
# --------------------------------------------------------------------------- #

# Internal sentinel values for TID lifecycle state.
_TID_RECEIVED = "received"
_TID_EXECUTED = "executed"
_TID_ROLLED_BACK = "rolled_back"


class InMemoryTidStore:
    """Thread-safe in-process TID store backed by a ``dict`` + ``threading.Lock``.

    Process-lifetime only — NOT durable (D-03). Data is lost on process restart.
    Production deployments must supply a custom durable store (e.g. PostgreSQL,
    Redis) that satisfies the :class:`TidStore` Protocol.

    Security (T-06-S01): TID keys are stored as-is in a Python dict. This is
    safe for dict keys; it is the responsibility of durable backend implementers
    to treat TID values as untrusted (parameterised queries, no concatenation).

    Concurrency (T-06-S03): a single ``threading.Lock`` guards all mutations.
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        # Maps tid -> one of _TID_RECEIVED, _TID_EXECUTED, _TID_ROLLED_BACK.
        self._store: dict[str, str] = {}
        # Maps tid -> parked payload bytes (D-03b park contract).
        self._parked: dict[str, bytes] = {}

    def is_executed(self, tid: str) -> bool:
        """Return True if ``tid`` has been marked as executed."""
        with self._lock:
            return self._store.get(tid) == _TID_EXECUTED

    def mark_received(self, tid: str) -> None:
        """Record that ``tid`` arrived; does NOT imply successful execution."""
        with self._lock:
            self._store[tid] = _TID_RECEIVED

    def mark_executed(self, tid: str) -> None:
        """Record successful execution of the function module for ``tid``."""
        with self._lock:
            self._store[tid] = _TID_EXECUTED

    def mark_rolled_back(self, tid: str) -> None:
        """Record rollback (error) for ``tid``; is_executed remains False."""
        with self._lock:
            self._store[tid] = _TID_ROLLED_BACK

    def confirm(self, tid: str) -> None:
        """Confirm ``tid`` and remove it from active tracking (cleanup)."""
        with self._lock:
            self._store.pop(tid, None)

    def park(self, tid: str, payload: bytes) -> None:
        """Store a copy of ``payload`` for later re-drive (D-03b).

        Does not alter TID state — is_executed() is unaffected.

        Security (T-06-S01): ``tid`` is peer-influenced untrusted input; used
        only as a Python dict key here (safe for in-process stores).
        """
        with self._lock:
            self._parked[tid] = bytes(payload)

    def get_parked(self, tid: str) -> bytes | None:
        """Return parked payload for ``tid``, or None if not parked (D-03b).

        Security (T-06-S01): ``tid`` used as Python dict key only (safe).
        """
        with self._lock:
            return self._parked.get(tid)

    def list_parked(self) -> list[str]:
        """Return a list of TIDs that currently have a parked payload (D-03b)."""
        with self._lock:
            return list(self._parked.keys())

    def delete_parked(self, tid: str) -> None:
        """Remove the parked payload for ``tid`` (D-03b).

        Security (T-06-S01): ``tid`` used as Python dict key only (safe).
        """
        with self._lock:
            self._parked.pop(tid, None)


# --------------------------------------------------------------------------- #
# InMemoryUnitStore — process-lifetime default (D-03)
# --------------------------------------------------------------------------- #


class InMemoryUnitStore:
    """Thread-safe in-process bgRFC Unit store backed by a ``dict`` + ``threading.Lock``.

    Process-lifetime only — NOT durable (D-03). Data is lost on process restart.
    Production deployments must supply a custom durable store that satisfies the
    :class:`UnitStore` Protocol.

    Unit state key is ``(unit_id, unit_type)`` so that the same ``unit_id``
    may coexist with different types (Pitfall 5 — 'T' and 'Q' are distinct).

    Security (T-06-S01): keys stored as-is in a Python dict; safe for in-process
    use. Durable backend implementers must parameterise all queries.

    Concurrency (T-06-S03): a single ``threading.Lock`` guards all mutations.
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        # Maps (unit_id, unit_type) -> UnitState
        self._store: dict[tuple[str, str], UnitState] = {}
        # Maps (unit_id, unit_type) -> parked payload bytes (D-03b park contract).
        self._parked: dict[tuple[str, str], bytes] = {}

    def get_unit_state(self, unit_id: str, unit_type: str) -> UnitState:
        """Return the :class:`UnitState` for ``(unit_id, unit_type)``.

        Returns :attr:`UnitState.NOT_FOUND` for unknown units.
        """
        with self._lock:
            return self._store.get((unit_id, unit_type), UnitState.NOT_FOUND)

    def persist(self, unit_id: str, unit_type: str) -> None:
        """Persist Unit; set state to :attr:`UnitState.IN_PROCESS`."""
        with self._lock:
            self._store[(unit_id, unit_type)] = UnitState.IN_PROCESS

    def confirm(self, unit_id: str, unit_type: str) -> None:
        """Confirm Unit; set state to :attr:`UnitState.CONFIRMED`."""
        with self._lock:
            self._store[(unit_id, unit_type)] = UnitState.CONFIRMED

    def park(self, unit_id: str, unit_type: str, payload: bytes) -> None:
        """Store a copy of ``payload`` for ``(unit_id, unit_type)`` (D-03b).

        Does not alter unit state — get_unit_state() is unaffected.

        Security (T-06-S01): keys used as Python tuple dict keys only (safe).
        """
        with self._lock:
            self._parked[(unit_id, unit_type)] = bytes(payload)

    def get_parked(self, unit_id: str, unit_type: str) -> bytes | None:
        """Return parked payload for ``(unit_id, unit_type)``, or None (D-03b)."""
        with self._lock:
            return self._parked.get((unit_id, unit_type))

    def list_parked(self) -> list[tuple[str, str]]:
        """Return all ``(unit_id, unit_type)`` pairs with a parked payload (D-03b)."""
        with self._lock:
            return list(self._parked.keys())

    def delete_parked(self, unit_id: str, unit_type: str) -> None:
        """Remove the parked payload for ``(unit_id, unit_type)`` (D-03b).

        Security (T-06-S01): keys used as Python tuple dict keys only (safe).
        """
        with self._lock:
            self._parked.pop((unit_id, unit_type), None)


# --------------------------------------------------------------------------- #
# SqliteTidStore — durable stdlib sqlite3 TID store (D-04 / D-05 / D-03b)
# --------------------------------------------------------------------------- #


class SqliteTidStore:
    """Durable, thread-safe TID store backed by stdlib ``sqlite3`` (D-04).

    Persists TID state across process restarts when a file path is supplied.
    Pass ``":memory:"`` for test isolation (ONE persistent connection per
    instance — Pitfall 5: each ``:memory:`` connection is a separate DB).

    Schema auto-migration (D-05 / Pitfall 3)
    -----------------------------------------
    Calls ``PRAGMA user_version`` on first open; if below
    :data:`_SCHEMA_VERSION` it creates the ``tids`` table with
    ``CREATE TABLE IF NOT EXISTS``.  No ``ALTER TABLE … ADD COLUMN IF NOT
    EXISTS`` is used (that form is **invalid** in SQLite).  Future column adds
    must gate on a ``user_version`` bump in ``_migrate()``.

    Security (T-09-02-SQLI / ASVS V5)
    -----------------------------------
    Every SQL statement uses ``?`` placeholders.  The ``tid`` argument is
    peer-influenced untrusted input — never f-string / ``%`` / ``.format``
    it into a query string.

    Concurrency
    -----------
    One persistent ``sqlite3`` connection per instance (opened in ``__init__``
    with ``check_same_thread=False``), shared across threads.  A
    ``threading.Lock`` serialises writes; reads also acquire the lock for
    simplicity and to avoid dirty reads on SQLite's default isolation level.

    Disk security (T-09-02-DISK — accepted)
    ----------------------------------------
    SQLite files are unencrypted.  Callers must not place the DB in a
    world-writable directory; this is the caller's responsibility.
    """

    def __init__(self, path: str = ":memory:") -> None:
        # ONE persistent connection for the store lifetime (Pitfall 5).
        # check_same_thread=False: safe because threading.Lock serialises access.
        self._db: sqlite3.Connection = sqlite3.connect(path, check_same_thread=False)
        self._lock: threading.Lock = threading.Lock()
        self._migrate()

    def _migrate(self) -> None:
        """Auto-migrate schema on first open (D-05 / Pitfall 3)."""
        with self._lock, self._db:
            # PRAGMA user_version does not support ? placeholders.
            # The version value is a code constant, NOT user input — safe literal.
            ver: int = self._db.execute("PRAGMA user_version").fetchone()[0]
            if ver < _SCHEMA_VERSION:
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS tids ("
                    "tid TEXT PRIMARY KEY,"
                    " state TEXT NOT NULL,"
                    " payload BLOB,"
                    " updated REAL"
                    ")"
                )
                # Set schema version — literal constant, not user data (safe).
                self._db.execute("PRAGMA user_version = 1")  # = _SCHEMA_VERSION

    # ---------------------------------------------------------------------- #
    # TidStore state methods
    # ---------------------------------------------------------------------- #

    def is_executed(self, tid: str) -> bool:
        """Return True if ``tid`` has been marked as executed.

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock:
            row = self._db.execute("SELECT state FROM tids WHERE tid = ?", (tid,)).fetchone()
        return row is not None and row[0] == _TID_EXECUTED

    def mark_received(self, tid: str) -> None:
        """Upsert ``tid`` to received state.

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO tids(tid, state, updated)"
                " VALUES(?, ?, strftime('%s', 'now'))"
                " ON CONFLICT(tid) DO UPDATE"
                " SET state = excluded.state, updated = excluded.updated",
                (tid, _TID_RECEIVED),
            )

    def mark_executed(self, tid: str) -> None:
        """Upsert ``tid`` to executed state.

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO tids(tid, state, updated)"
                " VALUES(?, ?, strftime('%s', 'now'))"
                " ON CONFLICT(tid) DO UPDATE"
                " SET state = excluded.state, updated = excluded.updated",
                (tid, _TID_EXECUTED),
            )

    def mark_rolled_back(self, tid: str) -> None:
        """Upsert ``tid`` to rolled_back state.

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO tids(tid, state, updated)"
                " VALUES(?, ?, strftime('%s', 'now'))"
                " ON CONFLICT(tid) DO UPDATE"
                " SET state = excluded.state, updated = excluded.updated",
                (tid, _TID_ROLLED_BACK),
            )

    def confirm(self, tid: str) -> None:
        """Delete ``tid`` from tracking (cleanup — removes from list_parked too).

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock, self._db:
            self._db.execute("DELETE FROM tids WHERE tid = ?", (tid,))

    # ---------------------------------------------------------------------- #
    # Park contract (D-03b)
    # ---------------------------------------------------------------------- #

    def park(self, tid: str, payload: bytes) -> None:
        """Persist serialised call bytes for later re-drive (D-03b).

        Upserts the row (creating with state=received if absent) and sets the
        ``payload`` column.  Does NOT alter an existing state column — a TID
        already in the executed state remains executed after parking.

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO tids(tid, state, payload, updated)"
                " VALUES(?, ?, ?, strftime('%s', 'now'))"
                " ON CONFLICT(tid) DO UPDATE"
                " SET payload = excluded.payload, updated = excluded.updated",
                (tid, _TID_RECEIVED, bytes(payload)),
            )

    def get_parked(self, tid: str) -> bytes | None:
        """Return the parked payload for ``tid``, or None if not parked (D-03b).

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock:
            row = self._db.execute("SELECT payload FROM tids WHERE tid = ?", (tid,)).fetchone()
        if row is None or row[0] is None:
            return None
        return bytes(row[0])

    def list_parked(self) -> list[str]:
        """Return TIDs that have a non-null parked payload (D-03b)."""
        with self._lock:
            rows = self._db.execute("SELECT tid FROM tids WHERE payload IS NOT NULL").fetchall()
        return [row[0] for row in rows]

    def delete_parked(self, tid: str) -> None:
        """Set the payload column to NULL for ``tid`` (D-03b).

        Security (T-09-02-SQLI): parameterised query; ``tid`` is untrusted.
        """
        with self._lock, self._db:
            self._db.execute("UPDATE tids SET payload = NULL WHERE tid = ?", (tid,))

    def close(self) -> None:
        """Close the underlying DB connection."""
        self._db.close()


# --------------------------------------------------------------------------- #
# SqliteUnitStore — durable stdlib sqlite3 Unit store (D-04 / D-05 / D-03b)
# --------------------------------------------------------------------------- #


class SqliteUnitStore:
    """Durable, thread-safe bgRFC Unit store backed by stdlib ``sqlite3`` (D-04).

    Keyed on ``(unit_id, unit_type)`` so that the same ``unit_id`` may coexist
    with different types (Pitfall 5 — 'T' and 'Q' are distinct bgRFC unit kinds).

    Schema auto-migration (D-05 / Pitfall 3)
    -----------------------------------------
    Same mechanism as :class:`SqliteTidStore`: uses ``PRAGMA user_version`` and
    ``CREATE TABLE IF NOT EXISTS``.  No invalid ``ALTER TABLE … IF NOT EXISTS``.

    Security (T-09-02-SQLI / ASVS V5)
    -----------------------------------
    Every SQL statement uses ``?`` placeholders.  ``unit_id`` and ``unit_type``
    are peer-influenced untrusted inputs — never interpolate them into SQL.

    Concurrency / Disk security
    ----------------------------
    Same guarantees as :class:`SqliteTidStore`.  One persistent connection per
    instance; ``threading.Lock`` serialises access; unencrypted on disk (caller
    responsibility — T-09-02-DISK accepted).
    """

    def __init__(self, path: str = ":memory:") -> None:
        # ONE persistent connection for the store lifetime (Pitfall 5).
        self._db: sqlite3.Connection = sqlite3.connect(path, check_same_thread=False)
        self._lock: threading.Lock = threading.Lock()
        self._migrate()

    def _migrate(self) -> None:
        """Auto-migrate schema on first open (D-05 / Pitfall 3)."""
        with self._lock, self._db:
            ver: int = self._db.execute("PRAGMA user_version").fetchone()[0]
            if ver < _SCHEMA_VERSION:
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS units ("
                    "unit_id TEXT NOT NULL,"
                    " unit_type TEXT NOT NULL,"
                    " state TEXT NOT NULL,"
                    " payload BLOB,"
                    " updated REAL,"
                    " PRIMARY KEY(unit_id, unit_type)"
                    ")"
                )
                # Set schema version — literal constant, not user data (safe).
                self._db.execute("PRAGMA user_version = 1")  # = _SCHEMA_VERSION

    # ---------------------------------------------------------------------- #
    # UnitStore state methods
    # ---------------------------------------------------------------------- #

    def get_unit_state(self, unit_id: str, unit_type: str) -> UnitState:
        """Return :class:`UnitState` for ``(unit_id, unit_type)``.

        Returns :attr:`UnitState.NOT_FOUND` for unknown units.

        Security (T-09-02-SQLI): parameterised query; both args are untrusted.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT state FROM units WHERE unit_id = ? AND unit_type = ?",
                (unit_id, unit_type),
            ).fetchone()
        if row is None:
            return UnitState.NOT_FOUND
        return UnitState(row[0])

    def persist(self, unit_id: str, unit_type: str) -> None:
        """Upsert unit to :attr:`UnitState.IN_PROCESS`.

        Security (T-09-02-SQLI): parameterised query; both args are untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO units(unit_id, unit_type, state, updated)"
                " VALUES(?, ?, ?, strftime('%s', 'now'))"
                " ON CONFLICT(unit_id, unit_type) DO UPDATE"
                " SET state = excluded.state, updated = excluded.updated",
                (unit_id, unit_type, UnitState.IN_PROCESS.value),
            )

    def confirm(self, unit_id: str, unit_type: str) -> None:
        """Upsert unit to :attr:`UnitState.CONFIRMED`.

        Security (T-09-02-SQLI): parameterised query; both args are untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO units(unit_id, unit_type, state, updated)"
                " VALUES(?, ?, ?, strftime('%s', 'now'))"
                " ON CONFLICT(unit_id, unit_type) DO UPDATE"
                " SET state = excluded.state, updated = excluded.updated",
                (unit_id, unit_type, UnitState.CONFIRMED.value),
            )

    # ---------------------------------------------------------------------- #
    # Park contract (D-03b)
    # ---------------------------------------------------------------------- #

    def park(self, unit_id: str, unit_type: str, payload: bytes) -> None:
        """Persist serialised call bytes for ``(unit_id, unit_type)`` (D-03b).

        Upserts the row and sets the ``payload`` column.  Does NOT alter an
        existing state column.

        Security (T-09-02-SQLI): parameterised query; both args are untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO units(unit_id, unit_type, state, payload, updated)"
                " VALUES(?, ?, ?, ?, strftime('%s', 'now'))"
                " ON CONFLICT(unit_id, unit_type) DO UPDATE"
                " SET payload = excluded.payload, updated = excluded.updated",
                (unit_id, unit_type, UnitState.IN_PROCESS.value, bytes(payload)),
            )

    def get_parked(self, unit_id: str, unit_type: str) -> bytes | None:
        """Return parked payload for ``(unit_id, unit_type)``, or None (D-03b).

        Security (T-09-02-SQLI): parameterised query; both args are untrusted.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM units WHERE unit_id = ? AND unit_type = ?",
                (unit_id, unit_type),
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return bytes(row[0])

    def list_parked(self) -> list[tuple[str, str]]:
        """Return ``(unit_id, unit_type)`` pairs with a non-null payload (D-03b)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT unit_id, unit_type FROM units WHERE payload IS NOT NULL"
            ).fetchall()
        return [(row[0], row[1]) for row in rows]

    def delete_parked(self, unit_id: str, unit_type: str) -> None:
        """Set the payload column to NULL for ``(unit_id, unit_type)`` (D-03b).

        Security (T-09-02-SQLI): parameterised query; both args are untrusted.
        """
        with self._lock, self._db:
            self._db.execute(
                "UPDATE units SET payload = NULL WHERE unit_id = ? AND unit_type = ?",
                (unit_id, unit_type),
            )

    def close(self) -> None:
        """Close the underlying DB connection."""
        self._db.close()


# --------------------------------------------------------------------------- #
# AsyncTidStore Protocol — async structural contract (D-08)
# --------------------------------------------------------------------------- #


@runtime_checkable
class AsyncTidStore(Protocol):
    """Async structural Protocol for tRFC/qRFC TID stores (D-08).

    Mirrors :class:`TidStore` with every method as ``async def``.  This is a
    structural contract for callers backing stores with async databases (e.g.
    ``aiosqlite``).  No concrete async implementation ships here — the sync
    :class:`SqliteTidStore` runs under ``asyncio.to_thread`` in 09-04.

    Security contract (T-06-S01)
    -----------------------------
    Same as :class:`TidStore`: ``tid`` values are peer-influenced untrusted
    input.  Implementers MUST use parameterised queries; never interpolate
    ``tid`` into SQL.
    """

    async def is_executed(self, tid: str) -> bool:
        """Return True if ``tid`` has already been executed (committed)."""
        ...

    async def mark_received(self, tid: str) -> None:
        """Record that ``tid`` has been received and is now in-flight."""
        ...

    async def mark_executed(self, tid: str) -> None:
        """Record that the function module for ``tid`` executed successfully."""
        ...

    async def mark_rolled_back(self, tid: str) -> None:
        """Record that the execution for ``tid`` was rolled back (error path)."""
        ...

    async def confirm(self, tid: str) -> None:
        """Confirm ``tid``; may remove or archive it from active tracking."""
        ...

    async def park(self, tid: str, payload: bytes) -> None:
        """Store serialised request bytes alongside TID state (D-03b).

        Security (T-06-S01): ``tid`` is peer-influenced untrusted input.
        """
        ...

    async def get_parked(self, tid: str) -> bytes | None:
        """Return the parked payload for ``tid``, or None if not parked (D-03b).

        Security (T-06-S01): ``tid`` is peer-influenced untrusted input.
        """
        ...

    async def list_parked(self) -> list[str]:
        """Return TIDs that have a non-null parked payload (D-03b)."""
        ...

    async def delete_parked(self, tid: str) -> None:
        """Remove the parked payload for ``tid`` (D-03b).

        Security (T-06-S01): ``tid`` is peer-influenced untrusted input.
        """
        ...


# --------------------------------------------------------------------------- #
# AsyncUnitStore Protocol — async structural contract (D-08)
# --------------------------------------------------------------------------- #


@runtime_checkable
class AsyncUnitStore(Protocol):
    """Async structural Protocol for bgRFC Unit stores (D-08).

    Mirrors :class:`UnitStore` with every method as ``async def``.  Structural
    contract for callers using async databases.  No concrete implementation
    ships here.

    Security contract (T-06-S01)
    -----------------------------
    Same as :class:`UnitStore`: ``unit_id`` and ``unit_type`` are
    peer-influenced untrusted inputs.  Implementers MUST use parameterised
    queries.
    """

    async def get_unit_state(self, unit_id: str, unit_type: str) -> UnitState:
        """Return the current :class:`UnitState` for ``(unit_id, unit_type)``.

        Returns ``UnitState.NOT_FOUND`` for unknown units.
        """
        ...

    async def persist(self, unit_id: str, unit_type: str) -> None:
        """Persist the Unit; transition state to at least ``IN_PROCESS``."""
        ...

    async def confirm(self, unit_id: str, unit_type: str) -> None:
        """Confirm the Unit; transition state to ``CONFIRMED`` or remove entry."""
        ...

    async def park(self, unit_id: str, unit_type: str, payload: bytes) -> None:
        """Store serialised request bytes for ``(unit_id, unit_type)`` (D-03b).

        Security (T-06-S01): both args are peer-influenced untrusted inputs.
        """
        ...

    async def get_parked(self, unit_id: str, unit_type: str) -> bytes | None:
        """Return parked payload for ``(unit_id, unit_type)``, or None (D-03b).

        Security (T-06-S01): both args are peer-influenced untrusted inputs.
        """
        ...

    async def list_parked(self) -> list[tuple[str, str]]:
        """Return ``(unit_id, unit_type)`` pairs with a non-null payload (D-03b)."""
        ...

    async def delete_parked(self, unit_id: str, unit_type: str) -> None:
        """Remove the parked payload for ``(unit_id, unit_type)`` (D-03b).

        Security (T-06-S01): both args are peer-influenced untrusted inputs.
        """
        ...
