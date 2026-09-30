# SPDX-License-Identifier: MPL-2.0
"""The metadata bootstrap: what runs before any first call to a function module.

``_call_bootstrap`` sends RFC_GET_FUNCTION_INTERFACE and turns the reply into a
FunctionDesc; ``_call_struct_bootstrap`` follows up with
RFC_GET_STRUCTURE_DEFINITION for every STRUCTURE parameter it found. Together
they are the largest untested block in the tree, and the reason is structural
rather than accidental: nearly every other test pre-populates the descriptor
cache so that ``call()`` skips the bootstrap entirely. The path that runs in
production against every function module the process has not seen before was the
one nothing exercised.

These drive it from the captured GFI replies instead of from a synthetic stub, so
the column layout, the EXID mapping and the compressed-table path are all
exercised as they actually arrive.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from saprfclib.connection import Connection
from saprfclib.exceptions import AbapApplicationError, IncompleteDescriptorError

from .test_connection import MockTransport, _handshake_responses

GOLDEN = Path(__file__).parent / "golden" / "framing"


def _conn_with(*responses: bytes) -> Connection:
    """A Connection at READY with an EMPTY descriptor cache, so the bootstrap runs."""
    conn = Connection(MockTransport(_handshake_responses() + list(responses)))
    conn._handshake(client="001", user="DEVELOPER", passwd="secret")
    return conn


def test_bootstrap_parses_a_real_gfi_reply() -> None:
    """44 parameters out of the captured BAPI_USER_GET_DETAIL interface."""
    conn = _conn_with((GOLDEN / "gfi_compressed_params_response.bin").read_bytes())
    desc = conn._call_bootstrap("BAPI_USER_GET_DETAIL")

    assert desc.name == "BAPI_USER_GET_DETAIL"
    assert len(desc.parameters) == 44

    by_name = {f.name: f for f in desc.parameters}
    # A STRUCTURE parameter (rfctype 17) with the width the interface declares.
    assert by_name["ADDRESS"].rfctype == 17
    assert by_name["ADDRESS"].nuc_length == 4256
    # Names round-trip uppercase and unpadded; a trailing-space bug here would
    # make every lookup miss without any error.
    assert all(f.name == f.name.strip() for f in desc.parameters)
    assert all(f.name for f in desc.parameters), "no blank parameter names"


def test_the_function_name_is_normalised_to_upper_case() -> None:
    """Callers pass mixed case; the cache and the wire both want one form."""
    conn = _conn_with((GOLDEN / "gfi_compressed_params_response.bin").read_bytes())
    desc = conn._call_bootstrap("bapi_user_get_detail")
    assert desc.name == "BAPI_USER_GET_DETAIL"


def test_an_unknown_function_surfaces_as_an_abap_error() -> None:
    """FU_NOT_FOUND is an answer, not a framing problem.

    It has to arrive as a typed ABAP error naming the function, rather than as a
    parse failure or an empty descriptor that fails confusingly later.
    """
    conn = _conn_with((GOLDEN / "gfi_fu_not_found_response.bin").read_bytes())
    with pytest.raises(AbapApplicationError) as excinfo:
        conn._call_bootstrap("Z_NO_SUCH_FUNCTION")
    assert "FU_NOT_FOUND" in str(excinfo.value)


def test_a_failed_struct_lookup_warns_and_names_what_is_missing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The degradation must be loud, and must say which type and which parameter.

    Only the GFI reply is scripted here, so every follow-up
    RFC_GET_STRUCTURE_DEFINITION runs off the end of the transport. The
    descriptor still comes back with all 44 parameters -- dropping them would be
    worse -- but each STRUCTURE one is left without a layout. Silence here would
    leave a later encode failing with nothing to say which lookup went wrong.
    """
    conn = _conn_with((GOLDEN / "gfi_compressed_params_response.bin").read_bytes())
    with caplog.at_level(logging.WARNING, logger="saprfclib.connection"):
        desc = conn._call_bootstrap("BAPI_USER_GET_DETAIL")

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings, "a layout that could not be fetched must not be silent"
    text = " ".join(r.getMessage() for r in warnings)
    assert "BAPIADDR3" in text, "the DDIC type that failed must be named"
    assert "ADDRESS" in text, "so must the parameter it belongs to"

    # The parameters survive; only their layouts are missing.
    assert len(desc.parameters) == 44
    assert all(f.type_desc is None for f in desc.parameters if f.rfctype == 17)


def test_a_parameter_without_a_layout_refuses_rather_than_guesses() -> None:
    """The other half of the contract: unusable, not silently wrong.

    A STRUCTURE field with no layout cannot be encoded. Encoding it as blanks or
    zeros would put a well-formed, meaningless record on the wire, so the codec
    raises instead.
    """
    from saprfclib.codec import encode

    conn = _conn_with((GOLDEN / "gfi_compressed_params_response.bin").read_bytes())
    desc = conn._call_bootstrap("BAPI_USER_GET_DETAIL")
    address = next(f for f in desc.parameters if f.name == "ADDRESS")
    assert address.type_desc is None
    with pytest.raises(IncompleteDescriptorError):
        encode(address.rfctype, {}, address)


def test_struct_layouts_are_cached_across_parameters() -> None:
    """BAPI interfaces reuse types heavily; refetching each would cost round trips.

    The cache is keyed by DDIC type name, so two parameters of the same type
    resolve with one lookup. Here every lookup fails, which still proves the
    point: 44 parameters produced one attempt per distinct type, not one per
    parameter.
    """
    conn = _conn_with((GOLDEN / "gfi_compressed_params_response.bin").read_bytes())
    attempted: list[str] = []
    conn._call_struct_bootstrap = lambda t: (  # type: ignore[method-assign]
        attempted.append(t),
        (_ for _ in ()).throw(OSError("no script")),
    )[1]
    conn._call_bootstrap("BAPI_USER_GET_DETAIL")
    assert attempted, "structure parameters must trigger a layout lookup"
    assert len(attempted) == len(set(attempted)), "each DDIC type looked up once"


def test_a_parameterless_interface_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    """RFC_PING has no parameters; an empty descriptor is correct for it.

    The warning fired on the row count alone, so it cried wolf on every
    parameterless function -- announcing that "the descriptor will be empty and
    calls will reject all arguments" about a fetch that had worked perfectly. A
    warning that fires on correct behaviour trains its reader to ignore it, which
    costs the one time it matters.
    """
    import struct

    from saprfclib.connection import _metadata_reply_succeeded
    from saprfclib.invoke import tlv_record as tr

    success = (
        tr(0x0500, b"")
        + tr(0x0503, b"")
        + tr(0x0420, struct.pack(">I", 0))
        + struct.pack(">HH", 0xFFFF, 0)
    )
    assert _metadata_reply_succeeded(success) is True


def test_parameterless_ping_reply_with_gw_header_does_not_crash(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RFC_PING's live reply still carries its GW header; the bootstrap must strip it.

    A live GFI reply begins with the 80-byte GW header (type 0x06CB). RFC_PING
    declares no parameters, so no PARAMS rows are parsed and the reply reaches
    _metadata_reply_succeeded. That helper walked the TLV stream from byte 0 and
    read the header type 0x06CB with the following 0x0200 as a bogus tag/length,
    raising "malformed TLV: tag 0x06cb length 512". Stripping the header first
    fixes it; this drives the real captured reply through the whole bootstrap.
    """
    reply = (GOLDEN / "ping_gfi_reply.bin").read_bytes()
    assert reply[:2] == b"\x06\xcb", "fixture must retain the live GW header"

    conn = _conn_with(reply)
    with caplog.at_level(logging.WARNING):
        desc = conn._call_bootstrap("RFC_PING")

    assert desc.name == "RFC_PING"
    assert desc.parameters == []
    # The reply reported success (0x0420 == 0, 0x0503 present), so no warning.
    assert "malformed TLV" not in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_metadata_reply_succeeded_strips_the_live_gw_header() -> None:
    """The direct unit: the raw captured reply, header and all, reads as success."""
    from saprfclib.connection import _metadata_reply_succeeded

    reply = (GOLDEN / "ping_gfi_reply.bin").read_bytes()
    assert _metadata_reply_succeeded(reply) is True


def test_a_reply_that_did_not_succeed_still_warns() -> None:
    """The complement: silencing the warning must not silence the real case."""
    import struct

    from saprfclib.connection import _metadata_reply_succeeded
    from saprfclib.invoke import tlv_record as tr

    # An exception marker means the fetch failed, however many rows came back.
    exception = (
        tr(0x0500, b"") + tr(0x0417, "001".encode("utf-16-le")) + struct.pack(">HH", 0xFFFF, 0)
    )
    assert _metadata_reply_succeeded(exception) is False

    # A non-zero return code, likewise.
    bad_rc = tr(0x0500, b"") + tr(0x0420, struct.pack(">I", 3)) + struct.pack(">HH", 0xFFFF, 0)
    assert _metadata_reply_succeeded(bad_rc) is False

    # And a reply carrying neither marker is not evidence of success.
    assert _metadata_reply_succeeded(tr(0x0500, b"")) is False
