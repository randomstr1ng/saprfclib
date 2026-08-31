# SPDX-License-Identifier: MPL-2.0
"""Failures in the server, pool and store paths must be reported, not absorbed.

Every case here was previously silent: the operation did not happen, and the caller
was told it did. They are grouped by what the silence costs — a bgRFC unit that
commits without running, a pool that hides why it timed out, a durable store that
opens a database it does not understand.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import uuid

import pytest

from saprfclib.invoke import _parse_tlv_stream, build_bgrfc_request
from saprfclib.server import _TAG_RETURN_CODE, RfcServer
from saprfclib.stores import InMemoryUnitStore, UnitState


def _return_code(response: bytes) -> int:
    tags = _parse_tlv_stream(response)
    rc = tags.get(_TAG_RETURN_CODE)
    assert rc is not None, "response carries no return code"
    return int(struct.unpack(">I", rc)[0])


def _new_server() -> RfcServer:
    return RfcServer({"program_id": "TEST", "gwhost": "localhost", "gwserv": "sapgw00"})


# --------------------------------------------------------------------------- #
# bgRFC: a unit that did not run must not be reported as committed
# --------------------------------------------------------------------------- #


def test_a_failed_call_is_not_erased_by_a_later_successful_one() -> None:
    """The unit must fail even when the failing call is not the last one.

    ``call_error`` was reassigned on every iteration, so a unit whose first call
    raised and whose second succeeded ended the loop with ``call_error = None`` and
    was committed and confirmed. The failure depended on nothing but call ordering.
    """
    server = _new_server()
    ran: list[str] = []

    @server.function("FAILING_FM")
    def _bad(request: dict) -> dict:
        ran.append("bad")
        raise RuntimeError("handler intentionally fails")

    @server.function("GOOD_FM")
    def _good(request: dict) -> dict:
        ran.append("good")
        return {}

    committed: list[str] = []
    rolled_back: list[str] = []
    server.install_unit_handlers(
        commit=lambda uid, ut: committed.append(uid),
        rollback=lambda uid, ut: rolled_back.append(uid),
    )
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    frame = build_bgrfc_request(
        uid,
        "T",
        [],
        buffered_calls=[
            "FAILING_FM".encode("utf-16-le"),
            "GOOD_FM".encode("utf-16-le"),
        ],
    )
    response = server.dispatch_inbound(frame)

    assert rolled_back == [uid]
    assert committed == []
    assert _return_code(response) != 0
    # A unit is one LUW and the caller re-ships the whole thing, so nothing after
    # the failure may run — it would execute twice on the resend.
    assert ran == ["bad"]


def test_an_undecodable_buffered_call_fails_the_unit() -> None:
    """A call that could not be decoded is not a call that ran."""
    server = _new_server()
    server.install_unit_handlers()
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    # Lone high surrogate: valid UTF-16 code units, not decodable as text.
    frame = build_bgrfc_request(uid, "T", [], buffered_calls=[b"\x00\xd8\x41\x00"])
    assert _return_code(server.dispatch_inbound(frame)) != 0


def test_an_empty_buffered_call_fails_the_unit() -> None:
    server = _new_server()
    server.install_unit_handlers()
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    frame = build_bgrfc_request(uid, "T", [], buffered_calls=[b""])
    assert _return_code(server.dispatch_inbound(frame)) != 0


def test_a_call_with_no_handler_still_fails_the_unit() -> None:
    """Unchanged behaviour, asserted so the fixes above cannot quietly relax it."""
    server = _new_server()
    server.install_unit_handlers()
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    frame = build_bgrfc_request(uid, "T", [], buffered_calls=["NO_SUCH_FM".encode("utf-16-le")])
    assert _return_code(server.dispatch_inbound(frame)) != 0


def test_dropped_call_parameters_are_reported(caplog: pytest.LogCaptureFixture) -> None:
    """The buffered-call parameter encoding is unimplemented (OG-06-02).

    Until it is, a handler runs against an empty request dict. Doing that to a
    business handler without saying so is the failure mode this whole file is about.
    """
    server = _new_server()
    seen: list[dict] = []

    @server.function("PARAM_FM")
    def _handler(request: dict) -> dict:
        seen.append(request)
        return {}

    server.install_unit_handlers()
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    # Name followed by a payload the call encoding cannot yet split out.
    call = "PARAM_FM".encode("utf-16-le") + b"\x00\x00" + "SOME_PAYLOAD".encode("utf-16-le")
    with caplog.at_level(logging.WARNING, logger="saprfclib.server"):
        response = server.dispatch_inbound(build_bgrfc_request(uid, "T", [], buffered_calls=[call]))

    assert _return_code(response) == 0
    assert seen == [{}]
    assert any("OG-06-02" in r.getMessage() for r in caplog.records)


def test_a_declared_but_missing_call_fails_the_unit() -> None:
    """A frame claiming more calls than it carries must not commit a partial LUW."""
    server = _new_server()
    server.install_unit_handlers()
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    frame = build_bgrfc_request(uid, "T", [], buffered_calls=["GOOD_FM".encode("utf-16-le")])
    # Overstate the count: the frame still carries only BGRFC_CALL_0.
    tampered = frame.replace(
        "1".encode("utf-16-le") + b"\x00" * 0,
        "4".encode("utf-16-le"),
        1,
    )
    if tampered == frame:
        pytest.skip("could not rewrite BGRFC_CALL_COUNT in this frame layout")
    assert _return_code(server.dispatch_inbound(tampered)) != 0


def test_a_failing_state_lookup_is_not_reported_as_not_found() -> None:
    """NOT_FOUND means "never seen"; the caller responds by shipping the unit again.

    Returning it when the lookup merely failed re-runs a possibly-committed LUW,
    which is the one thing the store exists to prevent.
    """
    from saprfclib.invoke import build_bgrfc_state_request

    server = _new_server()

    def _explode(unit_id: str, unit_type: str) -> UnitState:
        raise RuntimeError("state backend is down")

    server.install_unit_handlers(get_state=_explode)
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    response = server.dispatch_inbound(build_bgrfc_state_request(uid, "T"))
    assert _return_code(response) != 0
    assert b"NOT_FOUND" not in response


def test_a_throwing_unit_callback_is_isolated_but_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Isolation keeps the server alive; the log is what keeps the bug findable."""
    server = _new_server()

    @server.function("GOOD_FM")
    def _good(request: dict) -> dict:
        return {}

    server.install_unit_handlers(commit=lambda uid, ut: 1 / 0)
    server.set_unit_store(InMemoryUnitStore())

    uid = uuid.uuid4().hex.upper()
    frame = build_bgrfc_request(uid, "T", [], buffered_calls=["GOOD_FM".encode("utf-16-le")])
    with caplog.at_level(logging.ERROR, logger="saprfclib.server"):
        response = server.dispatch_inbound(frame)

    assert _return_code(response) == 0  # still isolated
    assert any("on_commit_unit" in r.getMessage() for r in caplog.records)
    assert any(r.exc_info for r in caplog.records)


# --------------------------------------------------------------------------- #
# Pool: a timeout must say why
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_async_pool_timeout_reports_the_discards_it_made() -> None:
    """``discarded`` separates "the pool is busy" from "the pool is churning".

    The async pool passed 0 unconditionally, so the field that tells those apart was
    a constant and every timeout looked like plain exhaustion.
    """
    from collections import deque

    from saprfclib.exceptions import PoolTimeoutError
    from saprfclib.pool import AsyncConnectionPool

    class _DeadConn:
        async def ping(self) -> bool:
            return False

        async def close(self) -> None:
            return None

    pool = AsyncConnectionPool.__new__(AsyncConnectionPool)
    pool._cond = asyncio.Condition()
    # One idle connection that fails its health check, and an open() that never
    # completes — so the wait times out after the pool has discarded something.
    pool._idle = deque([_DeadConn()])
    pool._in_use = set()
    pool._created = 1
    pool._max_size = 1
    pool._closed = False
    pool._discarded_total = 0

    async def _open() -> _DeadConn:
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    pool._open = _open  # type: ignore[method-assign]

    with pytest.raises(PoolTimeoutError) as excinfo:
        async with pool.acquire(timeout=0.25):
            pass
    assert excinfo.value.discarded > 0, "a churning pool must not report 0 discards"


def test_pool_logs_the_health_check_it_failed(caplog: pytest.LogCaptureFixture) -> None:
    from saprfclib.pool import ConnectionPool

    pool = ConnectionPool.__new__(ConnectionPool)

    class _Broken:
        def ping(self) -> bool:
            raise OSError("connection reset by peer")

    with caplog.at_level(logging.DEBUG, logger="saprfclib.pool"):
        assert pool._ping_ok(_Broken()) is False
    assert any("health check" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# Stores: never open a database this build does not understand
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("store_name", ["SqliteTidStore", "SqliteUnitStore"])
def test_sqlite_store_refuses_a_newer_schema(store_name: str, tmp_path) -> None:
    """A file from a later saprfclib must not be read through the older schema.

    The store's entire purpose is surviving a crash intact; degrading quietly to
    whatever this build happens to understand defeats it.
    """
    import sqlite3

    import saprfclib.stores as stores

    cls = getattr(stores, store_name)
    path = str(tmp_path / f"{store_name}.db")
    # Close it: a store holds its sqlite connection open for its lifetime, and a
    # leaked one is collected later and reported against whatever test is running
    # then -- which is how this suite has misattributed resource warnings before.
    created = cls(path)  # create at the current version
    created.close()

    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version = {stores._SCHEMA_VERSION + 1}")
    db.commit()
    db.close()

    with pytest.raises(RuntimeError, match="newer than this library supports"):
        cls(path)


@pytest.mark.parametrize("store_name", ["SqliteTidStore", "SqliteUnitStore"])
def test_sqlite_store_stamps_the_version_constant_not_a_literal(store_name: str, tmp_path) -> None:
    """The written version must track ``_SCHEMA_VERSION``.

    It was a repeated literal ``1``. Bumping the constant would have created the new
    schema and stamped it with the old number — so the next open would migrate again
    over live data and never notice.
    """
    import sqlite3

    import saprfclib.stores as stores

    path = str(tmp_path / f"{store_name}.db")
    store = getattr(stores, store_name)(path)
    store.close()
    db = sqlite3.connect(path)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == stores._SCHEMA_VERSION
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Server TABLE serialization — round-tripped through the client parser
# --------------------------------------------------------------------------- #


def _char_table_desc(name: str, width: int) -> object:
    """A one-column CHAR table descriptor, `width` characters wide."""
    from saprfclib.codec import RFCTYPE_CHAR
    from saprfclib.types import FieldDesc, TypeDesc

    return TypeDesc(
        name=f"{name}_ROW",
        fields=[
            FieldDesc(
                name="WA",
                rfctype=RFCTYPE_CHAR,
                nuc_length=width,
                nuc_offset=0,
                uc_length=width * 2,
                uc_offset=0,
                decimals=0,
            )
        ],
        nuc_size=width,
        uc_size=width * 2,
    )


def _server_table_func() -> object:
    from saprfclib.codec import RFCTYPE_TABLE
    from saprfclib.types import RFC_TABLES, FieldDesc, FunctionDesc

    return FunctionDesc(
        name="Z_TABLE_OUT",
        parameters=[
            FieldDesc(
                name="RESULTS",
                rfctype=RFCTYPE_TABLE,
                nuc_length=0,
                nuc_offset=0,
                uc_length=0,
                uc_offset=0,
                decimals=0,
                direction=RFC_TABLES,
                type_desc=_char_table_desc("RESULTS", 8),
                unicode_mode=True,
            )
        ],
    )


@pytest.mark.parametrize("row_count", [0, 1, 3, 17])
def test_server_serialized_table_reads_back_through_the_client_parser(row_count: int) -> None:
    """The server's TABLE output must be readable by our own client parser.

    ``_build_table_records`` had no test at all. Checking it against the client
    parser tests it against the other side of the wire rather than against itself:
    a wrong row stride or row count shows up as wrong data, not as a passing
    assertion about the bytes we just wrote.
    """
    from saprfclib.invoke import parse_invoke_response

    desc = _server_table_func()
    server = _new_server()
    rows = [{"WA": f"ROW{i:05d}"} for i in range(row_count)]

    response = server._build_response(desc, {"RESULTS": rows})
    parsed = parse_invoke_response(response, desc)

    if row_count == 0:
        # Declared by name only; the client may report it as absent or as empty,
        # but it must never report rows that were not sent.
        assert not parsed.get("RESULTS")
        return
    got = parsed["RESULTS"]
    assert len(got) == row_count, f"expected {row_count} rows, parser found {len(got)}"
    assert [r["WA"].rstrip() for r in got] == [r["WA"] for r in rows]


def test_server_refuses_a_table_it_cannot_lay_out() -> None:
    """A TABLE with no row descriptor must raise, not emit a nameless empty table."""
    from saprfclib.codec import RFCTYPE_TABLE
    from saprfclib.types import RFC_TABLES, FieldDesc

    field = FieldDesc(
        name="RESULTS",
        rfctype=RFCTYPE_TABLE,
        nuc_length=0,
        nuc_offset=0,
        uc_length=0,
        uc_offset=0,
        decimals=0,
        direction=RFC_TABLES,
        type_desc=None,
    )
    with pytest.raises(ValueError, match="row layout is missing"):
        RfcServer._build_table_records(field, [{"WA": "X"}], 1)


def test_a_missing_output_parameter_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Optional outputs may be omitted, but the omission should be findable."""
    desc = _server_table_func()
    server = _new_server()
    with caplog.at_level(logging.DEBUG, logger="saprfclib.server"):
        server._build_response(desc, {})
    assert any("RESULTS" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# examples/09_bapi_user_create.py — the --commit path
# --------------------------------------------------------------------------- #


def _load_example(name: str) -> object:
    """Import an example module by path (examples/ is not a package)."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).parent.parent / "examples" / name
    spec = importlib.util.spec_from_file_location(f"_example_{name[:2]}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_example_commit_detects_a_failure_reported_as_a_table() -> None:
    """A failed commit must be detected whichever shape RETURN arrives in.

    The check was ``isinstance(commit_return, dict)``. On a system whose
    BAPI_TRANSACTION_COMMIT answers with a RETURN *table*, an error row fell through
    it and the script printed "committed — user created" for a user that was not.
    """
    ex = _load_example("09_bapi_user_create.py")

    error_row = {"TYPE": "E", "MESSAGE": "Update was terminated", "ID": "RW", "NUMBER": "609"}
    assert ex.rows_failed(ex.as_return_rows(error_row)) is True  # structure
    assert ex.rows_failed(ex.as_return_rows([error_row])) is True  # table
    assert ex.rows_failed(ex.as_return_rows([{"TYPE": "S", "MESSAGE": "ok"}])) is False
    assert ex.rows_failed(ex.as_return_rows(None)) is False  # absent RETURN = success
    assert ex.rows_failed(ex.as_return_rows([])) is False


def test_example_refuses_an_unrecognised_return_shape() -> None:
    """Claiming success from a shape we did not understand is the failure mode."""
    ex = _load_example("09_bapi_user_create.py")
    with pytest.raises(TypeError, match="unexpected RETURN shape"):
        ex.as_return_rows("E")
    with pytest.raises(TypeError, match="non-row entry"):
        ex.as_return_rows([{"TYPE": "S"}, "not a row"])


def test_example_create_user_does_not_commit_after_a_bapi_error() -> None:
    """The staged-then-commit contract: an error row must stop the commit."""
    ex = _load_example("09_bapi_user_create.py")
    calls: list[str] = []

    class _Conn:
        def call(self, func: str, **kwargs: object) -> dict:
            calls.append(func)
            if func == "BAPI_USER_CREATE1":
                return {
                    "RETURN": [{"TYPE": "E", "MESSAGE": "User exists", "ID": "01", "NUMBER": "1"}]
                }
            return {"RETURN": {}}

    assert ex.create_user(_Conn(), "ZTEST", "pw") is False
    assert "BAPI_TRANSACTION_COMMIT" not in calls


def test_example_create_user_reports_a_failed_commit_as_failure() -> None:
    ex = _load_example("09_bapi_user_create.py")

    class _Conn:
        def call(self, func: str, **kwargs: object) -> dict:
            if func == "BAPI_USER_CREATE1":
                return {"RETURN": [{"TYPE": "S", "MESSAGE": "staged"}]}
            # Table-shaped commit failure — the case that used to read as success.
            return {"RETURN": [{"TYPE": "A", "MESSAGE": "Update was terminated"}]}

    assert ex.create_user(_Conn(), "ZTEST", "pw") is False


@pytest.mark.parametrize("store_name", ["SqliteTidStore", "SqliteUnitStore"])
def test_sqlite_store_closes_its_connection_when_open_fails(store_name: str, tmp_path) -> None:
    """A refused open must not leave the sqlite connection behind.

    ``__init__`` opens the database before validating its schema, so raising from
    the validation leaves the half-built object unreachable with a live handle. It
    is finalised at some arbitrary later point and the ResourceWarning lands on
    whichever unrelated test is running then — which is exactly how this suite
    misattributes leaks.
    """
    import gc
    import sqlite3
    import warnings

    import saprfclib.stores as stores

    cls = getattr(stores, store_name)
    path = str(tmp_path / f"{store_name}_leak.db")
    created = cls(path)
    created.close()

    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version = {stores._SCHEMA_VERSION + 1}")
    db.commit()
    db.close()

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        with pytest.raises(RuntimeError):
            cls(path)
        gc.collect()  # would raise ResourceWarning here if the handle leaked


# --------------------------------------------------------------------------- #
# EXID 'a' — DECFLOAT16 (live capture, A4H kernel 793, 2026-08-31)
# --------------------------------------------------------------------------- #


def test_exid_a_is_decfloat16() -> None:
    """A DECFLOAT16 parameter must survive metadata parsing.

    Live capture: a remote-enabled function module with seven DECFLOAT16 parameters
    on A4H (kernel 793) reported EXID 'a' for every one of them. 'a' was absent from
    the table, so each row raised and was dropped, and the descriptor came back
    holding only the DECFLOAT34 parameters — the call then went out missing seven
    arguments rather than failing.
    """
    from saprfclib.codec import RFCTYPE_DECF16, RFCTYPE_DECF34
    from saprfclib.metadata import _EXID_TO_RFCTYPE

    assert _EXID_TO_RFCTYPE["a"] == RFCTYPE_DECF16
    assert _EXID_TO_RFCTYPE["e"] == RFCTYPE_DECF34


def test_decfloat16_params_are_kept_in_the_descriptor() -> None:
    """The whole point: the parameter reaches the descriptor instead of vanishing."""
    from saprfclib.codec import RFCTYPE_DECF16
    from saprfclib.metadata import _parse_params_row

    row = {
        "PARAMCLASS": "E",
        "PARAMETER": "EV_TWELVE",
        "TABNAME": "",
        "FIELDNAME": "",
        "EXID": "a",
        "POSITION": "1",
        "OFFSET": "0",
        "INTLENGTH": "8",
        "DECIMALS": "0",
        "DEFAULT": "",
        "PARAMTEXT": "",
        "OPTIONAL": "",
    }
    field = _parse_params_row(row)
    assert field is not None
    assert field.name == "EV_TWELVE"
    assert field.rfctype == RFCTYPE_DECF16


def test_decfloat_still_refuses_to_guess_the_wire_encoding() -> None:
    """Parsing the metadata must not be mistaken for supporting the type.

    Now that a DECFLOAT16 parameter survives into the descriptor, a call carrying one
    reaches the codec — which must still raise rather than invent an encoding. The
    failure moves from "seven parameters silently missing" to "this type is not
    implemented", which is the correct shape for an unconfirmed wire format.
    """
    from saprfclib.codec import RFCTYPE_DECF16, RFCTYPE_DECF34, decode, encode

    for rfctype in (RFCTYPE_DECF16, RFCTYPE_DECF34):
        with pytest.raises(NotImplementedError, match="not implemented"):
            encode(rfctype, 1, None)
        with pytest.raises(NotImplementedError, match="not implemented"):
            decode(rfctype, b"\x00" * 8, None)
