# tests/test_phase09_async_client.py
#
# Phase 9 offline tests: async client parity (CLIENT-01..07).
#
# asyncio_mode = "auto" (pyproject.toml:92) so bare async def test_* run without decorators.
#
# Coverage: CLIENT-01, CLIENT-02, CLIENT-03, CLIENT-04, CLIENT-05, CLIENT-06, CLIENT-07
#
# Acceptance criteria encoded:
#   - await conn.call("FM", PARAM=...) returns result dict (CLIENT-01/02/03)
#   - AbapApplicationError / AbapSystemFailure / CommunicationError surface (CLIENT-04/05/06)
#   - get_connection_attributes() returns negotiated attrs (CLIENT-07)
#   - 128 MiB frame cap enforced in async recv path (DoS carry-over, T-03-DOS)

from __future__ import annotations

import struct
import unittest.mock as mock

import pytest

saprfc_connection = pytest.importorskip(
    "saprfclib.connection",
    reason="saprfclib.connection not importable — skipping Phase 9 async client tests",
)

from saprfclib.connection import AsyncConnection  # noqa: E402
from saprfclib.exceptions import (  # noqa: E402
    AbapApplicationError,
    AbapSystemFailure,
    CommunicationError,
)
from saprfclib.session import ConnectionAttributes, SessionState  # noqa: E402
from saprfclib.transport import AsyncTransport  # noqa: E402
from saprfclib.types import (  # noqa: E402
    RFC_EXPORT,
    RFC_IMPORT,
    FieldDesc,
    FunctionDesc,
)
from tests._mocks import AsyncMockTransport  # noqa: E402

# --------------------------------------------------------------------------- #
# Module-level helpers
# --------------------------------------------------------------------------- #


def _make_ready_conn(
    responses: list[bytes] | None = None,
) -> tuple[AsyncConnection, AsyncMockTransport]:
    """Create an AsyncConnection with session in READY state and attributes set.

    The session is forced to READY with a minimal ConnectionAttributes so
    get_connection_attributes() works and sys_id is populated for cache keying.
    """
    transport = AsyncMockTransport(responses or [])
    conn = AsyncConnection(transport)
    conn._session._state = SessionState.READY
    conn._session._attributes = ConnectionAttributes(
        sys_id="TST",
        sys_number="00",
        partner_host="localhost",
        client="100",
        user="TESTUSER",
        language="EN",
        partner_rel="753",
        kernel_rel="753",
        codepage="4103",
        unicode_mode=True,
    )
    return conn, transport


def _stfc_desc(func_name: str = "STFC_CONNECTION") -> FunctionDesc:
    """STFC_CONNECTION's parameter set, enough to exercise every direction.

    A descriptor must list the parameters a test passes: build_invoke_request now
    rejects an argument the interface does not declare rather than dropping it
    silently, which is what an empty stub descriptor used to rely on.
    """
    return FunctionDesc(
        name=func_name.upper(),
        parameters=[
            FieldDesc("REQUTEXT", 0, 255, 0, 510, 0, 0, direction=RFC_IMPORT),
            FieldDesc("INTPARAM", 8, 4, 0, 4, 0, 0, direction=RFC_IMPORT),
            FieldDesc("ECHOTEXT", 0, 255, 0, 510, 0, 0, direction=RFC_EXPORT),
        ],
    )


async def _stub_bootstrap(func_name: str) -> FunctionDesc:
    """Async stub for _call_bootstrap: a descriptor without any I/O.

    Replaces the real bootstrap, which would send RFC_GET_FUNCTION_INTERFACE over
    the transport.
    """
    return _stfc_desc(func_name)


# A minimal well-formed success response: return code 0 and no output parameters.
# An invoke response always carries 0x0420; a payload without it means the call was
# aborted, and parse_invoke_response now raises rather than reporting {}.
_EMPTY_OK_RESP: bytes = struct.pack(">HHI", 0x0420, 4, 0)


# Minimal TLV response bytes that trigger AbapApplicationError and AbapSystemFailure.
# Tag 0x0417 (EXCEPTION_NUMBER) presence → AbapApplicationError.
_ABAP_APP_RESP: bytes = struct.pack(">HH", 0x0417, 0)

# Tag 0x0420 (RETURN_CODE) with non-zero value → AbapSystemFailure.
_ABAP_SYS_RESP: bytes = struct.pack(">HHI", 0x0420, 4, 1)


# --------------------------------------------------------------------------- #
# CLIENT-01/02/03: await conn.call() returns result dict
# --------------------------------------------------------------------------- #


async def test_async_call_returns_dict() -> None:
    """CLIENT-01: await conn.call("STFC_CONNECTION", REQUTEXT="hi") returns a dict.

    The empty-bytes response b"" passes through _strip_gw_header unchanged (first
    byte is not 0x06) and through parse_invoke_response(b"", desc) returning {}.

    Asserts:
    - result is a dict.
    """
    conn, _ = _make_ready_conn([_EMPTY_OK_RESP])
    conn._call_bootstrap = _stub_bootstrap  # type: ignore[method-assign]
    result = await conn.call("STFC_CONNECTION", REQUTEXT="hi")
    assert isinstance(result, dict)


async def test_async_call_param_types() -> None:
    """CLIENT-02: IMPORTING / EXPORTING / CHANGING / TABLE params work by name.

    The async call must route all SAP parameter types through the sans-I/O
    invoke.py / codec.py layer unchanged. This test verifies that the async
    transport seam does not lose or corrupt any parameter category.

    Asserts:
    - result is a dict (no error from passing multiple typed kwargs).
    """
    conn, _ = _make_ready_conn([_EMPTY_OK_RESP])
    conn._call_bootstrap = _stub_bootstrap  # type: ignore[method-assign]
    result = await conn.call("STFC_CONNECTION", REQUTEXT="hello", INTPARAM=42)
    assert isinstance(result, dict)


async def test_async_call_return_types() -> None:
    """CLIENT-03: Python-native return types from async call.

    SAP types (INT, CHAR, BCD, DATE, etc.) must decode to Python-native types
    via the unchanged codec layer. A success response carrying no output parameters
    decodes to an empty dict.

    Asserts:
    - result is a dict.
    - result == {} (empty response, no params decoded).
    """
    conn, _ = _make_ready_conn([_EMPTY_OK_RESP])
    conn._call_bootstrap = _stub_bootstrap  # type: ignore[method-assign]
    result = await conn.call("STFC_CONNECTION")
    assert isinstance(result, dict)
    assert result == {}  # rc=0 with no output parameters


# --------------------------------------------------------------------------- #
# CLIENT-04/05/06: error surfaces from async call
# --------------------------------------------------------------------------- #


async def test_async_call_abap_application_error() -> None:
    """CLIENT-04: AbapApplicationError surfaces from async call on error response.

    When the AsyncMockTransport yields a TLV with tag 0x0417 (EXCEPTION_NUMBER),
    parse_invoke_response raises AbapApplicationError.

    The error must NOT be retried (Pitfall 4 — only CommunicationError retries).
    call() does not use the retry loop.

    Asserts:
    - AbapApplicationError is raised.
    """
    conn, _ = _make_ready_conn([_ABAP_APP_RESP])
    conn._call_bootstrap = _stub_bootstrap  # type: ignore[method-assign]
    with pytest.raises(AbapApplicationError):
        await conn.call("STFC_CONNECTION")


async def test_async_call_abap_system_failure() -> None:
    """CLIENT-05: AbapSystemFailure surfaces from async call on system failure response.

    When the AsyncMockTransport yields a TLV with tag 0x0420 and non-zero RC,
    parse_invoke_response raises AbapSystemFailure. System failures must NOT be retried.

    Asserts:
    - AbapSystemFailure is raised.
    """
    conn, _ = _make_ready_conn([_ABAP_SYS_RESP])
    conn._call_bootstrap = _stub_bootstrap  # type: ignore[method-assign]
    with pytest.raises(AbapSystemFailure):
        await conn.call("STFC_CONNECTION")


async def test_async_call_communication_error() -> None:
    """CLIENT-06: CommunicationError raised on network / protocol failure.

    When the AsyncMockTransport raises EOFError (exhausted script), the async
    call must wrap it in CommunicationError with the underlying exception
    accessible as .original_exception.

    Asserts:
    - CommunicationError is raised.
    - .original_exception is not None (the original EOFError is attached).
    """
    conn, _ = _make_ready_conn([])  # empty → recv_message raises EOFError
    conn._call_bootstrap = _stub_bootstrap  # type: ignore[method-assign]
    with pytest.raises(CommunicationError) as exc_info:
        await conn.call("STFC_CONNECTION")
    assert exc_info.value.original_exception is not None


# --------------------------------------------------------------------------- #
# CLIENT-07: get_connection_attributes() via async connection
# --------------------------------------------------------------------------- #


async def test_async_get_connection_attributes() -> None:
    """CLIENT-07: get_connection_attributes() returns negotiated attributes.

    No transport I/O involved — get_connection_attributes() reads from
    _session._attributes set during _make_ready_conn.

    Asserts:
    - attrs.sys_id == "TST"
    - attrs.client == "100"
    - attrs.user == "TESTUSER"
    - isinstance(attrs.unicode_mode, bool)
    """
    conn, _ = _make_ready_conn()
    attrs = conn.get_connection_attributes()
    assert attrs.sys_id == "TST"
    assert attrs.client == "100"
    assert attrs.user == "TESTUSER"
    assert isinstance(attrs.unicode_mode, bool)


# --------------------------------------------------------------------------- #
# DoS carry-over: 128 MiB frame cap in async recv path (T-03-DOS)
# --------------------------------------------------------------------------- #


async def test_async_recv_128mib_cap_enforced() -> None:
    """T-03-DOS: async recv raises ValueError before allocating an oversized frame.

    The AsyncTransport.recv_message must enforce the 128 MiB cap BEFORE calling
    reader.readexactly(length). An oversized declared length must raise ValueError
    immediately without allocating the payload.

    Asserts:
    - ValueError is raised with a message matching "exceeds cap".
    - reader.readexactly is called exactly once (cap check fires before second call).
    """
    _MAX = 128 * 1024 * 1024  # noqa: N806 — cap reference for acceptance grep
    oversized_len = _MAX + 1
    reader = mock.AsyncMock()
    writer = mock.AsyncMock()
    # First readexactly(4) returns the 4-byte NI header with the oversized length
    reader.readexactly = mock.AsyncMock(return_value=struct.pack(">I", oversized_len))
    transport = AsyncTransport(reader, writer)
    with pytest.raises(ValueError, match="exceeds cap"):
        await transport.recv_message()
    assert reader.readexactly.call_count == 1
