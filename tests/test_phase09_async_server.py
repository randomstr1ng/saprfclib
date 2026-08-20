# tests/test_phase09_async_server.py
#
# Phase 9 offline tests: AsyncRfcServer dispatch parity (D-08 / TRFC-03/07).
#
# asyncio_mode="auto" so bare async def test_* run without decorators.
#
# Coverage:
#   - Registering an async def handler and dispatching one inbound frame
#   - The awaited handler's dict is serialized back via dispatch_inbound core
#   - TRFC-03: server returns RFC_EXECUTED for a known TID (async store check)
#   - TRFC-07: bgRFC server callbacks fire in correct order with async handler

from __future__ import annotations

import struct

import pytest

saprfc_server = pytest.importorskip(
    "saprfclib.server",
    reason="saprfclib.server not importable — skipping Phase 9 async server tests",
)

AsyncRfcServer = getattr(saprfc_server, "AsyncRfcServer", None)
_SKIP_SERVER = pytest.mark.skipif(
    AsyncRfcServer is None,
    reason="AsyncRfcServer not yet in saprfclib.server (09-05 not landed)",
)

from saprfclib.invoke import (  # noqa: E402
    build_bgrfc_request,
    build_invoke_request,
    build_trfc_request,
)
from saprfclib.types import RFC_EXPORT, RFC_IMPORT, FieldDesc, FunctionDesc  # noqa: E402

# --------------------------------------------------------------------------- #
# Module-level helpers
# --------------------------------------------------------------------------- #


def _stfc_desc() -> FunctionDesc:
    """Build a FunctionDesc for STFC_CONNECTION with two parameters.

    REQUTEXT is RFC_IMPORT (caller sends), ECHOTEXT is RFC_EXPORT (caller reads).
    Both are RFCTYPE_CHAR (0) with 255 non-Unicode chars / 510 Unicode bytes.
    """
    return FunctionDesc(
        name="STFC_CONNECTION",
        parameters=[
            FieldDesc(
                name="REQUTEXT",
                rfctype=0,  # RFCTYPE_CHAR
                direction=RFC_IMPORT,
                nuc_length=255,
                nuc_offset=0,
                uc_length=510,
                uc_offset=0,
                decimals=0,
                unicode_mode=True,
            ),
            FieldDesc(
                name="ECHOTEXT",
                rfctype=0,  # RFCTYPE_CHAR
                direction=RFC_EXPORT,
                nuc_length=255,
                nuc_offset=0,
                uc_length=510,
                uc_offset=0,
                decimals=0,
                unicode_mode=True,
            ),
        ],
    )


# --------------------------------------------------------------------------- #
# Basic async handler registration and dispatch
# --------------------------------------------------------------------------- #


@_SKIP_SERVER
async def test_async_server_registers_and_dispatches_handler() -> None:
    """AsyncRfcServer dispatches one inbound frame to an async def handler.

    Registers `async def handler(request: dict) -> dict` for "STFC_CONNECTION"
    via the @server.function decorator.  Drives one inbound call frame through
    _async_dispatch (sans-I/O).  Asserts the handler is awaited exactly once and
    the response is non-empty bytes.

    Uses build_invoke_request to produce the inbound frame (starts with 0x0502,
    not 0x06 GW header) — no real socket or SAP gateway required.

    Asserts:
    - handler called exactly once.
    - response is bytes with non-zero length.
    """
    server = AsyncRfcServer({})
    call_count = 0

    @server.function("STFC_CONNECTION", _stfc_desc())
    async def handler(request: dict) -> dict:  # type: ignore[return]
        nonlocal call_count
        call_count += 1
        return {"ECHOTEXT": request.get("REQUTEXT", "")}

    frame = build_invoke_request("STFC_CONNECTION", _stfc_desc(), {"REQUTEXT": "test"})
    response = await server._async_dispatch(frame)

    assert call_count == 1
    assert isinstance(response, bytes)
    assert len(response) > 0


@_SKIP_SERVER
async def test_async_server_handler_is_async_def() -> None:
    """AsyncRfcServer accepts and awaits `async def` handlers.

    Registers an async handler coroutine and verifies the server awaits it
    (not calls it synchronously). If the server calls it without `await`, the
    coroutine object is returned instead of a dict, _build_response would raise
    or return a corrupt response. This test catches that regression.

    Asserts:
    - Registering an async def handler does not raise.
    - After _async_dispatch, was_awaited is True (the handler body executed).
    - Response is bytes (not a SYSTEM_FAILURE from coroutine-object mismatch).
    """
    server = AsyncRfcServer({})
    was_awaited = False

    @server.function("STFC_CONNECTION", _stfc_desc())
    async def async_handler(request: dict) -> dict:  # type: ignore[return]
        nonlocal was_awaited
        was_awaited = True
        return {}

    frame = build_invoke_request("STFC_CONNECTION", _stfc_desc(), {})
    response = await server._async_dispatch(frame)

    assert was_awaited, "async def handler was not awaited — coroutine ran synchronously"
    assert isinstance(response, bytes)


# --------------------------------------------------------------------------- #
# TRFC-03: server returns RFC_EXECUTED for a known TID
# --------------------------------------------------------------------------- #


@_SKIP_SERVER
async def test_async_server_duplicate_tid() -> None:
    """TRFC-03: AsyncRfcServer returns RFC_EXECUTED for a duplicate inbound TID.

    When an inbound tRFC frame arrives with a TID already marked as executed,
    the server must return the RFC_EXECUTED response (return code 16) without
    calling the handler a second time.

    This prevents double-execution of non-idempotent ABAP logic.  The test
    drives two identical inbound tRFC frames through _async_dispatch.

    Asserts:
    - Handler called exactly once across two identical tRFC frames.
    - Second dispatch response encodes return code 16 (RFC_EXECUTED).
    """
    server = AsyncRfcServer({})
    call_count = 0

    @server.function("STFC_CONNECTION")
    def handle(request: dict) -> dict:  # type: ignore[return]
        nonlocal call_count
        call_count += 1
        return {}

    tid = "ABCDEF1234567890ABCDEF12"  # 24 chars, valid RFC alphabet
    frame = build_trfc_request(tid, "STFC_CONNECTION")

    # First dispatch: TID is new → handler runs once
    resp1 = await server._async_dispatch(frame)
    assert call_count == 1
    assert isinstance(resp1, bytes)

    # Second dispatch: TID already executed → handler NOT called again
    resp2 = await server._async_dispatch(frame)
    assert call_count == 1  # still 1 — not re-invoked

    # RFC_EXECUTED return code (16 = 0x10) present in second response
    rc_executed = struct.pack(">I", 16)
    assert rc_executed in resp2


# --------------------------------------------------------------------------- #
# TRFC-07: bgRFC server callbacks fire in correct order
# --------------------------------------------------------------------------- #


@_SKIP_SERVER
async def test_async_server_bgrfc_callback_order() -> None:
    """TRFC-07: bgRFC server callbacks fire in check->commit->confirm order.

    The server must fire the bgRFC lifecycle callbacks in the correct sequence
    when an inbound bgRFC frame arrives:
      1. check   (is the unit already known? return 0 for new unit)
      2. commit  (LUW commit — logical unit of work complete)
      3. confirm (remove the unit from the store)

    No "rollback" must occur on the success path.

    Uses build_bgrfc_request to produce the inbound BGRFC_DEST_SHIP frame.
    _async_dispatch delegates to dispatch_inbound for bgRFC (synchronous store calls).

    Asserts:
    - Callbacks fire in ["check", "commit", "confirm"] order.
    - "rollback" not in order (no error on success path).
    """
    server = AsyncRfcServer({})
    order: list[str] = []

    unit_id = "1234567890ABCDEF1234567890ABCDEF"  # 32 uppercase hex chars

    server.install_unit_handlers(
        check=lambda uid, ut: (order.append("check"), 0)[1],
        commit=lambda uid, ut: order.append("commit"),
        rollback=lambda uid, ut: order.append("rollback"),
        confirm=lambda uid, ut: order.append("confirm"),
    )

    frame = build_bgrfc_request(unit_id, "T", [], None)
    response = await server._async_dispatch(frame)

    assert isinstance(response, bytes)
    assert order == ["check", "commit", "confirm"]
    assert "rollback" not in order
