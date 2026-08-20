# tests/test_metadata.py
#
# Unit tests for the saprfclib metadata layer (META-01..05).
#
# All tests are offline: uses a hand-built FunctionDesc (META-04), a mock
# fetch callback, the hard-coded bootstrap descriptor (META-05), and synthetic
# PARAMS-row dicts (META-01/02). No live SAP connection required.
#
# The exact RFC_GET_FUNCTION_INTERFACE result-table column layout is [ASSUMED]
# (RESEARCH A3 / META-01) — get_function_desc gates its uncached live-fetch path
# behind a documented NotImplementedError until a live capture confirms the wire
# layout (no-guessing constraint, same precedent as codec GAP-B-01).

import pytest

from saprfclib import decode, encode
from saprfclib.metadata import (
    BOOTSTRAP_GET_FUNCTION_INTERFACE,
    MetadataCache,
    get_function_desc,
)
from saprfclib.types import FieldDesc, FunctionDesc, TypeDesc

# RFCTYPE integer constants mirrored from the codec (codec.py lines 40-68).
CHAR, TABLE, INT, STRUCTURE = 0, 5, 8, 17


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #


class _StubConnection:
    """Minimal connection stand-in carrying only a sys_id for get_function_desc."""

    def __init__(self, sys_id: str = "A4H") -> None:
        self.sys_id = sys_id


def _params_row(
    *,
    parameter: str = "REQUTEXT",
    exid: str = "C",
    intlength: int = 510,
    offset: int = 0,
    decimals: int = 0,
    tabname: str = "",
    paramclass: str = "I",
) -> dict:
    """A synthetic RFC_GET_FUNCTION_INTERFACE PARAMS-table row.

    Column layout confirmed from live capture 2026-06-27 (META-01):
    EXID is a string type code ('C'=CHAR, 'I'=INT4, 'u'=STRUCTURE, 'h'=TABLE, etc.),
    INTLENGTH is unicode byte length, OFFSET is unicode byte offset.
    PARAMCLASS is 'I'=IMPORT, 'E'=EXPORT, 'C'=CHANGING, 'T'=TABLES (caller perspective).
    """
    return {
        "PARAMETER": parameter,
        "PARAMCLASS": paramclass,
        "EXID": exid,
        "INTLENGTH": intlength,
        "OFFSET": offset,
        "DECIMALS": decimals,
        "TABNAME": tabname,
    }


# --------------------------------------------------------------------------- #
# Task 1: cache + bootstrap + hand-built descriptor (META-03/04/05)
# --------------------------------------------------------------------------- #


def test_cache_hit_suppresses_second_fetch():
    """META-03: get_or_fetch returns the cached object and calls fetch once."""
    cache = MetadataCache()
    calls: list[str] = []

    def fetch(name: str) -> FunctionDesc:
        calls.append(name)
        return FunctionDesc(name=name.upper(), parameters=[])

    desc1 = cache.get_or_fetch("A4H", "STFC_CONNECTION", fetch)
    desc2 = cache.get_or_fetch("A4H", "STFC_CONNECTION", fetch)
    assert desc1 is desc2
    assert calls == ["STFC_CONNECTION"]


def test_cache_keyed_by_sysid():
    """META-03: same func name under two sys_ids does not collide."""
    cache = MetadataCache()
    a = FunctionDesc(name="STFC_CONNECTION", parameters=[])
    b = FunctionDesc(name="STFC_CONNECTION", parameters=[])
    cache.put("A4H", a)
    cache.put("B4H", b)
    assert cache.get("A4H", "STFC_CONNECTION") is a
    assert cache.get("B4H", "STFC_CONNECTION") is b
    assert cache.get("A4H", "STFC_CONNECTION") is not b


def test_cache_get_put_case_insensitive():
    """put/get normalize the func name to upper-case."""
    cache = MetadataCache()
    desc = FunctionDesc(name="Stfc_Connection", parameters=[])
    cache.put("A4H", desc)
    assert cache.get("A4H", "stfc_connection") is desc
    assert cache.get("A4H", "STFC_CONNECTION") is desc


def test_cache_miss_returns_none():
    """get returns None for an unknown sys_id or func name (no KeyError)."""
    cache = MetadataCache()
    assert cache.get("A4H", "NOPE") is None


def test_bootstrap_descriptor_usable():
    """META-05: the hard-coded bootstrap FunctionDesc breaks the chicken-and-egg."""
    desc = BOOTSTRAP_GET_FUNCTION_INTERFACE
    assert desc.name == "RFC_GET_FUNCTION_INTERFACE"
    assert len(desc.parameters) >= 1
    funcname_param = desc.parameters[0]
    assert isinstance(funcname_param, FieldDesc)
    assert funcname_param.name == "FUNCNAME"
    assert funcname_param.rfctype == CHAR
    assert funcname_param.nuc_length == 30
    assert funcname_param.uc_length == 60


def test_handbuilt_function_desc_codec_roundtrip():
    """META-04: a hand-built FieldDesc round-trips through saprfclib.encode/decode."""
    f = FieldDesc(
        name="X",
        rfctype=INT,
        nuc_length=4,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
    )
    desc = FunctionDesc(name="MY_FM", parameters=[f])
    assert desc.name == "MY_FM"
    wire = encode(INT, 42, f)
    assert wire == b"\x2a\x00\x00\x00"
    assert decode(INT, wire, f) == 42


# --------------------------------------------------------------------------- #
# Task 2: result-table parse + recursive TypeDesc, gated (META-01/02)
# --------------------------------------------------------------------------- #


def test_parse_params_row_to_fielddesc():
    """META-01: a confirmed PARAMS row maps to a FieldDesc with correct fields.

    Live capture (2026-06-27): CHAR(255) has INTLENGTH=510 (UTF-16, 2 bytes/char),
    OFFSET is unicode byte offset. nuc values are derived: CHAR → uc // 2.
    """
    from saprfclib.metadata import _parse_params_row

    row = _params_row(
        parameter="REQUTEXT",
        exid="C",  # CHAR
        intlength=510,  # unicode byte length (CHAR 255 * 2)
        offset=8,  # unicode byte offset
        decimals=0,
    )
    fd = _parse_params_row(row)
    assert isinstance(fd, FieldDesc)
    assert fd.name == "REQUTEXT"
    assert fd.rfctype == CHAR
    assert fd.nuc_length == 255  # 510 // 2 (char-like type)
    assert fd.nuc_offset == 4  # 8 // 2
    assert fd.uc_length == 510
    assert fd.uc_offset == 8
    assert fd.decimals == 0
    assert fd.type_desc is None  # scalar, no nesting


def test_parse_params_row_rejects_malformed_integer():
    """T-03-META: an unknown EXID code is rejected with ValueError."""
    from saprfclib.metadata import _parse_params_row

    row = _params_row()
    row["EXID"] = "not-a-valid-exid"
    with pytest.raises(ValueError):
        _parse_params_row(row)


def test_nested_structure_recurses():
    """META-02: STRUCTURE/TABLE fields expand into recursive TypeDesc (>=2 levels)."""
    from saprfclib.metadata import _build_type_desc

    # Two-level nest: outer TABLE -> inner STRUCTURE -> scalar leaf.
    inner_leaf = {
        "row": _params_row(parameter="LEAF", exid="C", intlength=20),
        "fields": [],
    }
    inner_struct = {
        "row": _params_row(parameter="INNER", exid="u", tabname="T_INNER"),
        "fields": [inner_leaf],
    }
    outer = {
        "row": _params_row(parameter="OUTER", exid="h", tabname="T_OUTER"),
        "fields": [inner_struct],
    }

    td = _build_type_desc("ROOT", [outer])
    assert isinstance(td, TypeDesc)
    outer_field = td.fields[0]
    assert outer_field.name == "OUTER"
    assert outer_field.rfctype == TABLE
    assert isinstance(outer_field.type_desc, TypeDesc)

    inner_field = outer_field.type_desc.fields[0]
    assert inner_field.name == "INNER"
    assert inner_field.rfctype == STRUCTURE
    assert isinstance(inner_field.type_desc, TypeDesc)

    leaf_field = inner_field.type_desc.fields[0]
    assert leaf_field.name == "LEAF"
    assert leaf_field.type_desc is None  # scalar leaf, no further nesting


def test_build_type_desc_rejects_excessive_depth():
    """T-03-META: pathological nesting depth is rejected (stack-exhaustion guard)."""
    from saprfclib.metadata import _build_type_desc

    # Build a node nested far deeper than the recursion cap.
    node = {"row": _params_row(parameter="L0", exid="C"), "fields": []}
    for i in range(64):
        node = {
            "row": _params_row(parameter=f"S{i}", exid="u", tabname=f"T{i}"),
            "fields": [node],
        }
    with pytest.raises(ValueError, match="depth"):
        _build_type_desc("ROOT", [node])


def test_get_function_desc_requires_connection_interface():
    """META-01: uncached live fetch requires connection._call_bootstrap (Phase 4).

    _StubConnection does not implement _call_bootstrap, so get_function_desc
    raises AttributeError rather than NotImplementedError (the gate is gone;
    the error is now a missing-method signal pointing to the correct fix).
    """
    conn = _StubConnection(sys_id="A4H")
    with pytest.raises(AttributeError, match="_call_bootstrap"):
        get_function_desc(conn, "STFC_CONNECTION")


def test_get_function_desc_uses_cache_when_present():
    """META-03: a cache hit short-circuits the unverified fetch (no gap)."""
    conn = _StubConnection(sys_id="A4H")
    cache = MetadataCache()
    cached = FunctionDesc(name="STFC_CONNECTION", parameters=[])
    cache.put("A4H", cached)

    result = get_function_desc(conn, "STFC_CONNECTION", cache=cache)
    assert result is cached


# --------------------------------------------------------------------------- #
# Task 1: PARAMCLASS → direction in _parse_params_row
# --------------------------------------------------------------------------- #


def test_parse_params_row_paramclass_I_maps_to_import():
    """PARAMCLASS='I' produces FieldDesc with direction=RFC_IMPORT (0x01).
    Confirmed from captures/phase03_metadata_STFC_CONNECTION.json: REQUTEXT has PARAMCLASS='I'."""
    from saprfclib.metadata import _parse_params_row
    from saprfclib.types import RFC_IMPORT

    row = _params_row(parameter="REQUTEXT", exid="C", intlength=510)
    row["PARAMCLASS"] = "I"
    fd = _parse_params_row(row)
    assert fd.direction == RFC_IMPORT


def test_parse_params_row_paramclass_E_maps_to_export():
    """PARAMCLASS='E' produces FieldDesc with direction=RFC_EXPORT (0x02).
    Confirmed: ECHOTEXT/RESPTEXT have PARAMCLASS='E' in the live capture."""
    from saprfclib.metadata import _parse_params_row
    from saprfclib.types import RFC_EXPORT

    row = _params_row(parameter="ECHOTEXT", exid="C", intlength=510)
    row["PARAMCLASS"] = "E"
    fd = _parse_params_row(row)
    assert fd.direction == RFC_EXPORT


def test_parse_params_row_paramclass_C_maps_to_changing():
    """PARAMCLASS='C' produces FieldDesc with direction=RFC_CHANGING (0x03)."""
    from saprfclib.metadata import _parse_params_row
    from saprfclib.types import RFC_CHANGING

    row = _params_row(parameter="STRU_INOUT", exid="u", intlength=40)
    row["PARAMCLASS"] = "C"
    fd = _parse_params_row(row)
    assert fd.direction == RFC_CHANGING


def test_parse_params_row_paramclass_T_maps_to_tables():
    """PARAMCLASS='T' produces FieldDesc with direction=RFC_TABLES (0x07)."""
    from saprfclib.metadata import _parse_params_row
    from saprfclib.types import RFC_TABLES

    row = _params_row(parameter="ROWS", exid="h", intlength=8)
    row["PARAMCLASS"] = "T"
    fd = _parse_params_row(row)
    assert fd.direction == RFC_TABLES


def test_parse_params_row_unknown_paramclass_raises():
    """Unknown PARAMCLASS raises ValueError rather than silently defaulting (T-03-META)."""
    from saprfclib.metadata import _parse_params_row

    row = _params_row(parameter="REQUTEXT", exid="C", intlength=510)
    row["PARAMCLASS"] = "X"  # not a valid PARAMCLASS code
    with pytest.raises(ValueError, match="PARAMCLASS"):
        _parse_params_row(row)
