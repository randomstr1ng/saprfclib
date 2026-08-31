# SPDX-License-Identifier: MPL-2.0
"""DECFLOAT16/34 wire codec — IEEE 754-2008 DPD, little-endian.

Every expectation here comes from tests/golden/serialization/decfloat_response.bin,
a live capture from A4H (kernel 793) of a remote-enabled function module returning
nine values whose decimal meaning was fixed in ABAP before the call. Nothing in this
file is inferred from the standard alone: the standard settles how DPD is laid out,
the capture settles that SAP uses DPD at all and in which byte order.
"""

from __future__ import annotations

import struct
from decimal import Decimal
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib.codec import (
    RFCTYPE_DECF16,
    RFCTYPE_DECF34,
    decode,
    decode_decfloat,
    encode,
    encode_decfloat,
)
from saprfclib.types import FieldDesc

GOLDEN = Path(__file__).parent / "golden" / "serialization" / "decfloat_response.bin"

# The values the ABAP function module was written to return, by parameter name.
EXPECTED = {
    "EV_TWELVE_16": "12",
    "EV_TWELVE_34": "12",
    "EV_FORTY_TWO_DOT_ZERO": "42.0",
    "EV_MINUS_ONE": "-1",
    "EV_ZERO": "0",
    "EV_WIDE_16": "1234567890123456",
    "EV_WIDE_34": "1234567890123456789012345678901234",
    # Not supplied by the caller, so ABAP returns the type's initial value.
    "EV_ECHO_16": "0",
    "EV_ECHO_34": "0",
}


def _captured_values() -> dict[str, bytes]:
    """Pull the name/value pairs straight out of the captured frame."""
    body = GOLDEN.read_bytes()[80:]
    out: dict[str, bytes] = {}
    name = ""
    pos = 0
    while pos + 4 <= len(body):
        tag, length = struct.unpack_from(">HH", body, pos)
        pos += 4
        if tag == 0xFFFF:
            break
        if length == 0xFFFF:
            length = struct.unpack_from(">I", body, pos)[0]
            pos += 4
        if pos + length > len(body):
            break
        val = body[pos : pos + length]
        pos += length
        if pos + 2 <= len(body) and struct.unpack_from(">H", body, pos)[0] == tag:
            pos += 2
        if tag == 0x0201:
            name = val.decode("utf-16-le").rstrip("\x00 ")
        elif tag == 0x0203 and name:
            out[name] = val
            name = ""
    return out


def test_the_fixture_carries_every_expected_parameter() -> None:
    """Guards the test data itself: a truncated fixture must not silently pass."""
    captured = _captured_values()
    missing = set(EXPECTED) - set(captured)
    assert not missing, f"fixture is missing {sorted(missing)}"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_captured_value_decodes_to_what_abap_returned(name: str) -> None:
    raw = _captured_values()[name]
    assert str(decode_decfloat(raw)) == EXPECTED[name]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_encoding_reproduces_the_captured_bytes(name: str) -> None:
    """Byte-exact in the other direction, against the same live evidence."""
    raw = _captured_values()[name]
    assert encode_decfloat(Decimal(EXPECTED[name]), len(raw)) == raw


def test_the_wire_is_little_endian() -> None:
    """The order the docs previously recorded as big-endian, disproven by capture.

    DECFLOAT16 42.0 is `22 34 00 00 00 00 02 20` in DPD as IEEE lays it out.
    It arrives on the wire byte-reversed. Reading it big-endian yields
    4.00000000801022E-128 — a plausible-looking number, not an error, which is
    exactly why this needed a capture rather than a reasonable assumption.
    """
    raw = _captured_values()["EV_FORTY_TWO_DOT_ZERO"]
    assert raw == bytes.fromhex("2002000000003422")
    assert raw[::-1] == bytes.fromhex("2234000000000220")
    assert decode_decfloat(raw) == Decimal("42.0")
    assert decode_decfloat(raw[::-1]) != Decimal("42.0")


def test_twelve_is_what_separates_dpd_from_bid() -> None:
    """DPD packs three digits per ten bits, so twelve is 0x12 and not 0x0c.

    One captured value of known magnitude settles the scheme outright.
    """
    assert _captured_values()["EV_TWELVE_16"][0] == 0x12
    assert decode_decfloat(bytes.fromhex("1200000000003822")) == Decimal(12)


def _field(rfctype: int) -> FieldDesc:
    width = 8 if rfctype == RFCTYPE_DECF16 else 16
    return FieldDesc(
        name="V",
        rfctype=rfctype,
        nuc_length=width,
        nuc_offset=0,
        uc_length=width,
        uc_offset=0,
        decimals=0,
    )


@pytest.mark.parametrize("rfctype", [RFCTYPE_DECF16, RFCTYPE_DECF34])
def test_public_encode_decode_route_to_the_codec(rfctype: int) -> None:
    """encode()/decode() must stop raising NotImplementedError for these types."""
    field = _field(rfctype)
    raw = encode(rfctype, Decimal("42.0"), field)
    assert len(raw) == (8 if rfctype == RFCTYPE_DECF16 else 16)
    assert decode(rfctype, raw, field) == Decimal("42.0")


@pytest.mark.parametrize("rfctype", [RFCTYPE_DECF16, RFCTYPE_DECF34])
def test_never_float(rfctype: int) -> None:
    """A base-10 decimal that binary float cannot hold must survive exactly."""
    field = _field(rfctype)
    value = Decimal("0.1")
    assert decode(rfctype, encode(rfctype, value, field), field) == value
    assert decode(rfctype, encode(rfctype, value, field), field) != Decimal(0.1)


def test_width_is_validated() -> None:
    with pytest.raises(ValueError, match="8 or 16 bytes"):
        decode_decfloat(b"\x00" * 4)
    with pytest.raises(ValueError, match="8 or 16"):
        encode_decfloat(Decimal(1), 12)


def test_too_many_digits_is_refused_not_silently_rounded() -> None:
    """Truncating a decimal to fit is the corruption this type exists to avoid."""
    with pytest.raises(ValueError, match="significant digits"):
        encode_decfloat(Decimal("1" * 17), 8)
    with pytest.raises(ValueError, match="significant digits"):
        encode_decfloat(Decimal("1" * 35), 16)


def test_out_of_range_exponent_is_refused() -> None:
    with pytest.raises(ValueError, match="outside the DECFLOAT"):
        encode_decfloat(Decimal("1E+400"), 8)


@pytest.mark.parametrize("text", ["Infinity", "-Infinity", "NaN", "-NaN"])
@pytest.mark.parametrize("width", [8, 16])
def test_specials_round_trip(text: str, width: int) -> None:
    got = decode_decfloat(encode_decfloat(Decimal(text), width))
    assert str(got) == text


@given(
    coefficient=st.integers(min_value=-(10**16 - 1), max_value=10**16 - 1),
    exponent=st.integers(min_value=-20, max_value=20),
)
def test_decf16_round_trips(coefficient: int, exponent: int) -> None:
    """decode(encode(x)) == x — the property example-based tests miss."""
    value = Decimal(coefficient).scaleb(exponent)
    if len(value.as_tuple().digits) > 16:
        return
    assert decode_decfloat(encode_decfloat(value, 8)) == value


@given(
    coefficient=st.integers(min_value=-(10**34 - 1), max_value=10**34 - 1),
    exponent=st.integers(min_value=-40, max_value=40),
)
def test_decf34_round_trips(coefficient: int, exponent: int) -> None:
    value = Decimal(coefficient).scaleb(exponent)
    if len(value.as_tuple().digits) > 34:
        return
    assert decode_decfloat(encode_decfloat(value, 16)) == value
