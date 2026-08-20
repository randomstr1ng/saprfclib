# tests/test_types.py
#
# Unit tests for the saprfclib descriptor dataclasses (D-02 FieldDesc, D-07 TypeDesc).
# Phase 2 builds FieldDesc/TypeDesc instances by hand; Phase 3 fills them from live DDIC metadata.

from __future__ import annotations

from saprfclib.types import FieldDesc, FunctionDesc, TypeDesc


def test_fielddesc_constructs_with_defaults() -> None:
    """D-02: FieldDesc carries the codec's field metadata; unicode_mode defaults True,
    type_desc defaults None."""
    f = FieldDesc(
        "X",
        rfctype=8,
        nuc_length=4,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
    )
    assert f.name == "X"
    assert f.rfctype == 8
    assert f.nuc_length == 4
    assert f.nuc_offset == 0
    assert f.uc_length == 4
    assert f.uc_offset == 0
    assert f.decimals == 0
    assert f.unicode_mode is True
    assert f.type_desc is None


def test_typedesc_holds_field_list() -> None:
    """D-07: TypeDesc holds its field list plus nuc/uc total sizes."""
    f = FieldDesc(
        "X",
        rfctype=8,
        nuc_length=4,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
    )
    t = TypeDesc("S", fields=[f], nuc_size=10, uc_size=20)
    assert t.name == "S"
    assert t.fields == [f]
    assert t.nuc_size == 10
    assert t.uc_size == 20


def test_fielddesc_type_desc_forward_reference_round_trips() -> None:
    """D-07: FieldDesc.type_desc points to a nested TypeDesc for STRUCTURE/TABLE fields;
    the forward reference resolves."""
    inner = FieldDesc(
        "INNER",
        rfctype=0,
        nuc_length=2,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
    )
    nested = TypeDesc("NESTED", fields=[inner], nuc_size=2, uc_size=4)
    outer = FieldDesc(
        "OUTER",
        rfctype=17,
        nuc_length=2,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
        type_desc=nested,
    )
    assert outer.type_desc is nested
    assert outer.type_desc.fields[0].name == "INNER"


def test_functiondesc_stub_constructs() -> None:
    """FunctionDesc is a Phase-3 stub; parameters default to an empty list."""
    fn = FunctionDesc("STFC_STRUCTURE")
    assert fn.name == "STFC_STRUCTURE"
    assert fn.parameters == []


# --------------------------------------------------------------------------- #
# Task 1: FieldDesc.direction (RFC_DIRECTION from PARAMCLASS)
# --------------------------------------------------------------------------- #


def test_fielddesc_direction_defaults() -> None:
    """FieldDesc.direction defaults to RFC_IMPORT so existing Phase 2 hand-built
    descriptors keep working without modification."""
    from saprfclib.types import RFC_IMPORT

    f = FieldDesc(
        "X",
        rfctype=8,
        nuc_length=4,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
    )
    assert f.direction == RFC_IMPORT


def test_rfc_direction_constants_match_sapnwrfc_h() -> None:
    """RFC_DIRECTION constants mirror sapnwrfc.h lines 644-650:
    RFC_IMPORT=0x01, RFC_EXPORT=0x02, RFC_CHANGING=0x03, RFC_TABLES=0x07."""
    from saprfclib.types import RFC_CHANGING, RFC_EXPORT, RFC_IMPORT, RFC_TABLES

    assert RFC_IMPORT == 0x01
    assert RFC_EXPORT == 0x02
    assert RFC_CHANGING == 0x03
    assert RFC_TABLES == 0x07


def test_fielddesc_direction_settable() -> None:
    """FieldDesc.direction can be set to any RFC_DIRECTION value."""
    from saprfclib.types import RFC_EXPORT

    f = FieldDesc(
        "Y",
        rfctype=0,
        nuc_length=2,
        nuc_offset=0,
        uc_length=4,
        uc_offset=0,
        decimals=0,
        direction=RFC_EXPORT,
    )
    assert f.direction == RFC_EXPORT
