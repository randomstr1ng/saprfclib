# SPDX-License-Identifier: MPL-2.0
"""The public-API gaps a downstream integration hit, and what closes them.

Source: porting the FortiSOAR "SAP NetWeaver" connector off pyrfc. Each test here
pins one thing that integration needed and could not get, so the workaround it
shipped can be deleted rather than kept in step with us.
"""

from __future__ import annotations

import datetime as dt
import inspect
from decimal import Decimal

import pytest

import saprfclib
from saprfclib.connection import Connection
from saprfclib.metadata import _parse_params_row
from saprfclib.session import Session

# --------------------------------------------------------------------------- #
# Gap 1: the interface metadata must survive into the descriptor
# --------------------------------------------------------------------------- #


def _row(**over: object) -> dict[str, object]:
    """A minimal RFC_GET_FUNCTION_INTERFACE PARAMS row."""
    row: dict[str, object] = {
        "PARAMCLASS": "I",
        "PARAMETER": "QUERY_TABLE",
        "TABNAME": "DD02L",
        "FIELDNAME": "TABNAME",
        "EXID": "C",
        "POSITION": 1,
        "OFFSET": 0,
        "INTLENGTH": 60,
        "DECIMALS": 0,
        "DEFAULT": "",
        "PARAMTEXT": "",
        "OPTIONAL": "",
    }
    row.update(over)
    return row


def test_optional_default_and_text_reach_the_field_descriptor() -> None:
    """The three columns a UI needs are decoded off the wire and were discarded.

    An integration rendering a form over a function's interface needs all three:
    OPTIONAL decides whether the field is required, DEFAULT prefills it,
    PARAMTEXT labels it. The wire parser already read them; only the descriptor
    dropped them, so the caller had to fetch and parse the interface a second
    time to recover data this library had already had in hand.
    """
    field = _parse_params_row(_row(OPTIONAL="X", DEFAULT="'DD02L'", PARAMTEXT="Table to read"))
    assert field.optional is True
    assert field.default_value == "'DD02L'"
    assert field.param_text == "Table to read"


def test_a_required_parameter_reports_optional_false() -> None:
    field = _parse_params_row(_row(OPTIONAL=""))
    assert field.optional is False


def test_blank_default_and_text_become_none_not_empty_string() -> None:
    """Blank and absent must read alike, and neither may look like a real value.

    These columns are space-padded on the wire, so "" means the server sent
    nothing. A caller prefilling a form has to tell "no default" from "the
    default is the empty string", and only None says the first.
    """
    field = _parse_params_row(_row(DEFAULT="   ", PARAMTEXT=""))
    assert field.default_value is None
    assert field.param_text is None

    missing = _row()
    del missing["DEFAULT"]
    del missing["PARAMTEXT"]
    assert _parse_params_row(missing).default_value is None


def test_the_new_fields_do_not_disturb_the_layout_numbers() -> None:
    """They are inert for the codec; adding them must not move a single offset."""
    field = _parse_params_row(_row(OPTIONAL="X", PARAMTEXT="anything"))
    assert (field.uc_length, field.uc_offset) == (60, 0)
    assert (field.nuc_length, field.nuc_offset) == (30, 0)


# --------------------------------------------------------------------------- #
# Gap 2: an explicit gateway port
# --------------------------------------------------------------------------- #


def test_connect_accepts_an_explicit_port() -> None:
    """3300 + sysnr does not survive NAT, a port-forward or a jump host.

    The convention is right for a gateway reachable at its own address, and the
    library cannot derive anything else. Asserted on the signature rather than by
    connecting: the behaviour under test is that the parameter exists and
    defaults to None, which is what keeps the derivation in place for everyone
    who does not pass it.
    """
    for fn in (saprfclib.connect, saprfclib.connect_async):
        params = inspect.signature(fn).parameters
        assert "port" in params, fn.__name__
        assert params["port"].default is None, fn.__name__
        assert params["port"].kind is inspect.Parameter.KEYWORD_ONLY, fn.__name__


# --------------------------------------------------------------------------- #
# Gap 3: the sync connection is a context manager
# --------------------------------------------------------------------------- #


class _ClosableTransport:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def _bare_connection() -> tuple[Connection, _ClosableTransport]:
    """A Connection with just enough state for close() to run.

    Built without __init__ on purpose: what is under test is the context-manager
    protocol, and opening a real connection would drag a socket into an offline
    test. close() marks the session CLOSED and closes the transport, so it needs
    both attributes present.
    """
    conn = Connection.__new__(Connection)
    transport = _ClosableTransport()
    conn._transport = transport  # type: ignore[assignment]
    conn._session = Session()
    conn._async_conn = None
    conn._loop_thread = None
    return conn, transport


def test_connection_closes_itself_on_leaving_a_with_block() -> None:
    """AsyncConnection had __aenter__/__aexit__; the sync one had nothing.

    Every caller wrote the same try/finally, and the one who forgot leaked a
    connection and the gateway conversation with it.
    """
    conn, transport = _bare_connection()

    with conn as entered:
        assert entered is conn
        assert transport.closed == 0
    assert transport.closed == 1


def test_the_connection_is_closed_even_when_the_block_raises() -> None:
    conn, transport = _bare_connection()

    with pytest.raises(RuntimeError, match="boom"), conn:
        raise RuntimeError("boom")
    assert transport.closed == 1


# --------------------------------------------------------------------------- #
# Gap 4: pyrfc exception aliases
# --------------------------------------------------------------------------- #


def test_compat_aliases_point_at_the_real_exception_classes() -> None:
    """A missed rename during a port is silent, not an ImportError.

    With pyrfc still installed alongside — which it is, mid-migration — an
    unrewritten ``except ABAPApplicationError`` resolves against pyrfc, matches
    nothing this library raises, and the handler quietly stops running.
    """
    from saprfclib import compat

    assert compat.ABAPApplicationError is saprfclib.AbapApplicationError
    assert compat.ABAPRuntimeError is saprfclib.AbapSystemFailure
    assert compat.CommunicationError is saprfclib.CommunicationError
    assert compat.ExternalRuntimeError is saprfclib.SapRfcError
    assert compat.LogonError is saprfclib.CommunicationError


def test_compat_names_are_not_reachable_from_the_package_root() -> None:
    """They must be imported deliberately, never acquired by accident.

    Two spellings of the same hierarchy in the public namespace is how a codebase
    ends up with both, indefinitely.
    """
    for name in ("ABAPApplicationError", "ABAPRuntimeError", "ExternalRuntimeError"):
        assert not hasattr(saprfclib, name), name
        assert name not in saprfclib.__all__, name


# --------------------------------------------------------------------------- #
# Gap 5: jsonable()
# --------------------------------------------------------------------------- #


def test_jsonable_converts_every_type_the_codec_decodes_to() -> None:
    result = {
        "WHEN": dt.date(2026, 9, 17),
        "AT": dt.time(14, 30, 0),
        "STAMP": dt.datetime(2026, 9, 17, 14, 30, 0),
        "AMOUNT": Decimal("12.50"),
        "RAW": b"\xde\xad\xbe\xef",
        "TEXT": "unchanged",
        "COUNT": 7,
    }
    assert saprfclib.jsonable(result) == {
        "WHEN": "2026-09-17",
        "AT": "14:30:00",
        "STAMP": "2026-09-17T14:30:00",
        "AMOUNT": "12.50",
        "RAW": "deadbeef",
        "TEXT": "unchanged",
        "COUNT": 7,
    }


def test_jsonable_renders_a_decimal_as_a_string_never_a_float() -> None:
    """The one conversion that would silently corrupt data if it went to float.

    float(Decimal("0.1")) is not 0.1. A currency amount that survived the wire
    intact must not lose precision on the way out of the library, and a consumer
    that wants a number can parse the string with its own rounding.
    """
    out = saprfclib.jsonable(Decimal("0.1"))
    assert out == "0.1"
    assert isinstance(out, str)
    assert saprfclib.jsonable(Decimal("12345678901234567890.123")) == ("12345678901234567890.123")


def test_jsonable_recurses_through_tables_and_nested_structures() -> None:
    """A call() result is dicts of lists of dicts; one pass must handle all of it."""
    assert saprfclib.jsonable({"DATA": [{"WA": Decimal("1.5")}, {"WA": Decimal("2.5")}]}) == {
        "DATA": [{"WA": "1.5"}, {"WA": "2.5"}]
    }


def test_jsonable_leaves_strings_whole() -> None:
    """str is a Sequence; walking it would explode every string into characters."""
    assert saprfclib.jsonable(["ab", "cd"]) == ["ab", "cd"]
    assert saprfclib.jsonable({"K": "value"}) == {"K": "value"}


def test_jsonable_output_actually_serialises() -> None:
    """The point of the helper, asserted end to end rather than field by field."""
    import json

    payload = {
        "ROWS": [{"WHEN": dt.date(2026, 1, 2), "AMT": Decimal("3.40"), "ID": b"\x01\x02"}],
    }
    assert json.loads(json.dumps(saprfclib.jsonable(payload))) == {
        "ROWS": [{"WHEN": "2026-01-02", "AMT": "3.40", "ID": "0102"}],
    }


def test_the_metadata_survives_the_whole_wire_path_not_just_a_hand_built_row() -> None:
    """End to end over a captured response, because the rows above are synthetic.

    The tests above feed ``_parse_params_row`` a dict assembled in the test, which
    proves the mapping and nothing about whether those columns survive the TLV
    walk that produces the dict. This drives the real path: a captured
    RFC_GET_FUNCTION_INTERFACE reply through ``_parse_gfi_params_rows`` and then
    into descriptors.

    Source: tests/golden/framing/gfi_compressed_params_response.bin —
    BAPI_USER_GET_DETAIL, 44 parameter rows, of which 27 are optional, 44 carry a
    description and one carries a default.
    """
    import pathlib

    from saprfclib.connection import _parse_gfi_params_rows

    raw = (
        pathlib.Path(__file__).parent / "golden" / "framing" / "gfi_compressed_params_response.bin"
    ).read_bytes()
    fields = [_parse_params_row(row) for row in _parse_gfi_params_rows(raw)]
    assert len(fields) == 44

    by_name = {f.name: f for f in fields}

    # The one parameter in this capture with a server-supplied default.
    cache = by_name["CACHE_RESULTS"]
    assert cache.optional is True
    assert cache.default_value == "'X'"
    assert cache.param_text == "Temporarily buffer results in work process"

    # Descriptions are present on every row; optionality varies, which is what
    # makes it worth carrying rather than assuming.
    assert all(f.param_text for f in fields)
    assert sum(f.optional for f in fields) == 27
    assert not by_name["ADDRESS"].optional
    assert by_name["ADDRESS"].default_value is None
