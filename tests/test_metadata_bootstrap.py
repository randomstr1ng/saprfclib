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


def test_ddif_dfies_row_layout_parses_from_capture() -> None:
    """The DDIF_FIELDINFO_GET DFIES_TAB layout for a UC-unit reply (RFCSI).

    RFCSI's reply reports Unicode-unit lengths. The type-driven builder derives
    the layout from LENG + type rather than trusting the reply's offset column, so
    RFCDEST (CHAR32) lands at UC offset 26 with 64 UC bytes and the structure is
    490 UC bytes -- the layout verified end to end against a live RFCSI_EXPORT.
    """
    from saprfclib.connection import _build_type_desc_from_ddif, _parse_ddif_dfies_rows

    raw = (GOLDEN / "ddif_fieldinfo_rfcsi_response.bin").read_bytes()
    rows = _parse_ddif_dfies_rows(raw)
    assert len(rows) == 20

    td = _build_type_desc_from_ddif("RFCSI", rows)
    assert td.uc_size == 490
    by_name = {f.name: f for f in td.fields}
    assert by_name["RFCDEST"].uc_offset == 26
    assert by_name["RFCDEST"].uc_length == 64
    assert by_name["RFCIPV6ADDR"].uc_offset == 400


def test_ddif_nuc_unit_reply_builds_unicode_widths() -> None:
    """A NUC-unit DFIES reply must still yield Unicode widths (regression).

    35 of 36 captured structures report NUC (single-byte) internal lengths; only
    RFCSI reports Unicode ones. Trusting the reply's INTLEN column as Unicode bytes
    (the first cut of this code) produced half-width descriptors for the 35 —
    BAPILOGOND at 379 UC bytes instead of 730, its leading DATS field 8 bytes
    instead of 16 — which silently corrupts the decode of every field after it. The
    type-driven builder derives widths from LENG + type, so a char field is 2 bytes
    per character and a DATS is 16 bytes regardless of the reply's unit.
    """
    from saprfclib.connection import _build_type_desc_from_ddif, _parse_ddif_dfies_rows

    raw = (GOLDEN / "ddif_fieldinfo_bapilogond_response.bin").read_bytes()
    rows = _parse_ddif_dfies_rows(raw)
    assert len(rows) == 14

    td = _build_type_desc_from_ddif("BAPILOGOND", rows)
    assert td.uc_size == 730  # not 379 (the half-width NUC-as-UC bug)
    by_name = {f.name: f for f in td.fields}
    # DATS: 8 characters => 16 Unicode bytes, per the SAP_UC rule.
    assert by_name["GLTGV"].uc_length == 16
    assert by_name["GLTGV"].nuc_length == 8
    # CHAR1 => 2 Unicode bytes; a RAW field is a byte count, not doubled.
    assert by_name["USTYP"].uc_length == 2
    assert by_name["BCODE"].uc_length == 8  # RAW(8) — binary, same in both units
    # Fields pack tightly and in position order.
    assert by_name["GLTGB"].uc_offset == 16
    assert by_name["USTYP"].uc_offset == 32


def test_struct_bootstrap_resolves_rfcsi_via_ddif_fieldinfo() -> None:
    """The whole secondary bootstrap: DDIF_FIELDINFO_GET first, layout resolved.

    The reference library resolves DDIC layouts with DDIF_FIELDINFO_GET, and so
    must we — an endpoint that answers RFC_GET_STRUCTURE_DEFINITION with an empty
    FIELDS table left RFCSI_EXPORT (and every BAPI structure) with no layout,
    which surfaced downstream as IncompleteDescriptorError. Driving the real
    captured reply proves the DDIF path resolves the 20 RFCSI fields, and that
    the request that went out was DDIF_FIELDINFO_GET.
    """
    reply = (GOLDEN / "ddif_fieldinfo_rfcsi_response.bin").read_bytes()
    conn = _conn_with(reply)

    td = conn._call_struct_bootstrap("RFCSI")

    assert td.name == "RFCSI"
    assert len(td.fields) == 20
    assert td.uc_size == 490
    assert [f.name for f in td.fields][:2] == ["RFCPROTO", "RFCCHARTYP"]

    sent = b"".join(conn._transport.sent)  # type: ignore[attr-defined]
    assert "DDIF_FIELDINFO_GET".encode("utf-16-le") in sent
    assert "RFC_GET_STRUCTURE_DEFINITION".encode("utf-16-le") not in sent


def test_struct_bootstrap_falls_back_to_rsd_when_ddif_is_empty() -> None:
    """When DDIF returns no field rows, fall back to RFC_GET_STRUCTURE_DEFINITION.

    Both replies here are the endpoint's empty success (rc 0, no FIELDS table), so
    the fallback is attempted and, being empty too, the layout genuinely cannot be
    resolved and 'no DFIES rows' is raised. The point is that the fallback ran:
    both function names appear on the wire, DDIF first.
    """
    empty = (GOLDEN / "struct_definition_empty_response.bin").read_bytes()
    conn = _conn_with(empty, empty)

    with pytest.raises(ValueError, match="no DFIES rows"):
        conn._call_struct_bootstrap("RFCSI")

    sent = b"".join(conn._transport.sent)  # type: ignore[attr-defined]
    assert "DDIF_FIELDINFO_GET".encode("utf-16-le") in sent
    assert "RFC_GET_STRUCTURE_DEFINITION".encode("utf-16-le") in sent


def test_ddif_builder_types_integers_from_datatype_not_inttype() -> None:
    """INT4/INT2/INT1/RAW all share INTTYPE 'X'; DATATYPE must disambiguate them.

    On a live system (confirmed against DD03L and a 29k-structure export) an INT4
    field reports INTTYPE 'X', identical to RAW. Typing by INTTYPE alone decodes
    every integer as raw bytes. _build_type_desc_from_ddif types from the DDIC
    DATATYPE instead. Rows are (fieldname, position, offset, leng, intlen,
    decimals, datatype). This is a Unicode reply (CHAR INTLEN == 2*LENG), so the
    server's OFFSET column is used verbatim -- including the alignment padding it
    encodes (RATE, an 8-byte float, sits at 32 though SHORT ends at 26).
    """
    from saprfclib.codec import (
        RFCTYPE_BYTE,
        RFCTYPE_CHAR,
        RFCTYPE_FLOAT,
        RFCTYPE_INT,
        RFCTYPE_INT2,
    )
    from saprfclib.connection import _build_type_desc_from_ddif

    rows = [
        # (name, position, OFFSET, LENG, INTLEN, decimals, DATATYPE)
        ("NAME", 1, 0, 10, 20, 0, "CHAR"),  # 0..20
        ("COUNT", 2, 20, 10, 4, 0, "INT4"),  # 20..24 ; INTTYPE would be 'X'
        ("SHORT", 3, 24, 5, 2, 0, "INT2"),  # 24..26
        ("RATE", 4, 32, 16, 8, 0, "FLTP"),  # 32..40 ; 6 bytes align padding before it
        ("BLOB", 5, 40, 8, 8, 0, "RAW"),  # 40..48 ; RAW also INTTYPE 'X'
    ]
    td = _build_type_desc_from_ddif("ZTEST", rows)
    by = {f.name: f for f in td.fields}

    assert by["COUNT"].rfctype == RFCTYPE_INT  # not RFCTYPE_BYTE
    assert by["SHORT"].rfctype == RFCTYPE_INT2
    assert by["RATE"].rfctype == RFCTYPE_FLOAT
    assert by["BLOB"].rfctype == RFCTYPE_BYTE
    assert by["NAME"].rfctype == RFCTYPE_CHAR

    # Server OFFSET used verbatim, alignment gap preserved.
    assert by["NAME"].uc_offset == 0 and by["NAME"].uc_length == 20
    assert by["COUNT"].uc_offset == 20 and by["COUNT"].uc_length == 4
    assert by["SHORT"].uc_offset == 24 and by["SHORT"].uc_length == 2
    assert by["RATE"].uc_offset == 32 and by["RATE"].uc_length == 8  # aligned, not 26
    assert by["BLOB"].uc_offset == 40 and by["BLOB"].uc_length == 8
    assert td.uc_size == 48


def test_ddif_builder_uses_server_offsets_with_real_alignment() -> None:
    """A Unicode reply's server OFFSET is authoritative — alignment padding included.

    Real fields from a live DDIF_FIELDINFO_GET(TABNAME='SYST', ALL_TYPES='X')
    reply (SAP kernel, Unicode). LANGU (CHAR1) ends at 202, but MODNO (INT4) is at
    204 — the server pads 2 bytes to reach a 4-byte boundary. DEBUG (CHAR1) is at
    194 though the DEC field before it ends at 193 (2-byte alignment). A tight
    packer would place MODNO at 202 and mis-slice everything after it, so the
    builder must take the server's OFFSET verbatim. Rows are (name, position,
    offset, leng, intlen, decimals, datatype).
    """
    from saprfclib.codec import RFCTYPE_BCD, RFCTYPE_CHAR, RFCTYPE_INT
    from saprfclib.connection import _build_type_desc_from_ddif

    rows = [
        ("CCURT", 50, 188, 9, 5, 0, "DEC"),
        ("DEBUG", 51, 194, 1, 2, 0, "CHAR"),  # 194, not 193 (2-byte align)
        ("CTYPE", 52, 196, 1, 2, 0, "CHAR"),
        ("INPUT", 53, 198, 1, 2, 0, "CHAR"),
        ("LANGU", 54, 200, 1, 2, 0, "LANG"),  # ends at 202
        ("MODNO", 55, 204, 10, 4, 0, "INT4"),  # 204, not 202 (4-byte align)
        ("BATCH", 56, 208, 1, 2, 0, "CHAR"),
    ]
    td = _build_type_desc_from_ddif("SYST", rows)
    by = {f.name: f for f in td.fields}

    assert by["MODNO"].uc_offset == 204  # alignment padding preserved, not 202
    assert by["MODNO"].rfctype == RFCTYPE_INT
    assert by["DEBUG"].uc_offset == 194  # not 193
    assert by["DEBUG"].rfctype == RFCTYPE_CHAR
    assert by["CCURT"].rfctype == RFCTYPE_BCD
    assert by["LANGU"].uc_offset == 200
