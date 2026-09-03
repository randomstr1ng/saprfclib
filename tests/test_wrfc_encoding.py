# SPDX-License-Identifier: MPL-2.0
"""wRFC (ngrfc V1) value encoding.

Pure byte-building — no socket, no live system — but it was almost entirely
uncovered because the only tests that reached it were integration tests needing
a WebSocket RFC endpoint. Every field here is fixed-width, which in this codebase
has been the reliable place to find silent corruption.
"""

from __future__ import annotations

import struct
from decimal import Decimal

import pytest

from saprfclib.codec import (
    RFCTYPE_BCD,
    RFCTYPE_CHAR,
    RFCTYPE_DATE,
    RFCTYPE_INT,
    RFCTYPE_NUM,
    RFCTYPE_TIME,
)
from saprfclib.connection import (
    _MAX_FUNC_NAME_LEN,
    _pad_call_name,
    _v1_enc_bcd,
    _v1_enc_int,
    _v1_enc_string,
    _v1_enc_xstring,
    _v1_encode_char_value,
    _v1_type_name,
)

# --------------------------------------------------------------------------- #
# Call-name padding
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("length", [1, 8, 20, 30])
def test_call_name_fields_are_exactly_the_documented_width(length: int) -> None:
    name = "F" * length
    assert len(_pad_call_name(name, 30)) == 32
    assert len(_pad_call_name(name, 38)) == 40


def test_an_over_long_function_name_is_refused() -> None:
    """The pad count goes negative and yields an EMPTY string, not a shorter one.

    So an over-long name produced a field that was too LONG: 31 characters gave a
    33-character call-begin field where the format requires 32, with nothing
    raising. ABAP caps function module names at 30, so such a name is invalid
    anyway — but building a malformed frame is the wrong way to say so.
    """
    assert _MAX_FUNC_NAME_LEN == 30
    with pytest.raises(ValueError, match="characters"):
        _pad_call_name("F" * 31, 30)
    with pytest.raises(ValueError, match="characters"):
        _pad_call_name("F" * 40, 38)


# --------------------------------------------------------------------------- #
# Fixed-width value encoding
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "nuc", "uc"),
    [("AB", 4, 8), ("", 4, 8), ("ABCD", 4, 8), ("ABCDEFGH", 4, 8), ("Ä", 4, 8)],
)
def test_char_values_are_padded_to_the_declared_width(value: str, nuc: int, uc: int) -> None:
    """One 'O' marker byte then exactly uc_length bytes — blank-padded, truncated.

    Fixed-width is the contract: short values are space-padded and over-long ones
    are cut. Both matter, and this codebase has repeatedly found the second half
    missing.
    """
    encoded = _v1_encode_char_value(value, nuc, uc)
    assert encoded[:1] == b"O", "compMode marker"
    assert len(encoded) == 1 + uc, f"{value!r} produced {len(encoded) - 1} bytes, field is {uc}"


def test_char_values_are_blank_padded_not_nul_padded() -> None:
    """ABAP CHAR is blank-padded; NUL padding would read back as a different value."""
    assert _v1_encode_char_value("AB", 4, 8) == b"OA\x00B\x00 \x00 \x00"


def test_an_over_long_char_value_is_truncated_to_the_field() -> None:
    """It cannot grow the field — the declared width is what the server reads."""
    full = _v1_encode_char_value("ABCD", 4, 8)
    over = _v1_encode_char_value("ABCDEFGH", 4, 8)
    assert over == full, "the value must be cut at the field width, not overflow it"


@pytest.mark.parametrize(
    ("value", "width", "signed"),
    [
        (0, 4, True),
        (1, 4, True),
        (-1, 4, True),
        (2**31 - 1, 4, True),
        (255, 1, False),
        (0, 2, True),
        (-32768, 2, True),
        (2**63 - 1, 8, True),
    ],
)
def test_integers_encode_to_their_exact_width(value: int, width: int, signed: bool) -> None:
    """One compMode marker byte (0x4E) then the value, little-endian, fixed width."""
    encoded = _v1_enc_int(value, width, signed)
    assert encoded[:1] == b"\x4e", "compMode marker"
    assert len(encoded) == 1 + width, f"{value} produced {len(encoded) - 1} value bytes"


def test_an_out_of_range_integer_is_refused_not_wrapped() -> None:
    """Silently wrapping would send a different number than the caller passed."""
    with pytest.raises(struct.error):
        _v1_enc_int(2**31, 4, True)
    with pytest.raises(struct.error):
        _v1_enc_int(-1, 1, False)


@pytest.mark.parametrize(
    ("value", "nuc", "decimals"),
    [
        (Decimal("0"), 8, 2),
        (Decimal("1.23"), 8, 2),
        (Decimal("-1.23"), 8, 2),
        (Decimal("99999.99"), 8, 2),
        (Decimal("1"), 16, 0),
    ],
)
def test_bcd_encodes_to_the_declared_width(value: Decimal, nuc: int, decimals: int) -> None:
    """Packed decimal is fixed-width; a short field would change the value."""
    encoded = _v1_enc_bcd(value, nuc, decimals)
    assert encoded[:1] == b"\x4e", "compMode marker"
    assert len(encoded) == 1 + nuc


def test_bcd_sign_nibble_distinguishes_negative() -> None:
    """0xC positive, 0xD negative — the sign lives in the last nibble, not a byte."""
    pos = _v1_enc_bcd(Decimal("1.23"), 8, 2)
    neg = _v1_enc_bcd(Decimal("-1.23"), 8, 2)
    assert pos[-1] & 0x0F == 0x0C
    assert neg[-1] & 0x0F == 0x0D
    assert pos[:-1] == neg[:-1], "only the sign nibble may differ"


def test_a_bcd_value_too_large_for_the_field_is_refused() -> None:
    """Truncating a decimal to fit is the corruption BCD exists to prevent."""
    with pytest.raises(OverflowError, match="overflows"):
        _v1_enc_bcd(Decimal("9" * 20), 8, 0)


def test_bcd_round_values_are_exact() -> None:
    """0.1 has no exact binary float representation; BCD must carry it exactly."""
    assert _v1_enc_bcd(Decimal("0.10"), 8, 2) == _v1_enc_bcd(Decimal("0.1"), 8, 2)
    # 1.15 and 1.14999... differ in BCD even though they are close in float.
    assert _v1_enc_bcd(Decimal("1.15"), 8, 2) != _v1_enc_bcd(Decimal("1.14"), 8, 2)


@pytest.mark.parametrize(
    ("rfctype", "nuc"),
    [
        (RFCTYPE_CHAR, 10),
        (RFCTYPE_DATE, 8),
        (RFCTYPE_TIME, 6),
        (RFCTYPE_NUM, 4),
        (RFCTYPE_INT, 4),
        (RFCTYPE_BCD, 8),
    ],
)
def test_every_supported_type_has_a_wire_type_name(rfctype: int, nuc: int) -> None:
    name = _v1_type_name(rfctype, nuc)
    assert isinstance(name, bytes) and name, f"rfctype {rfctype} produced no type name"


# --------------------------------------------------------------------------- #
# Variable-length values
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["", "x", "hello world", "ä" * 10, "x" * 5000])
def test_strings_encode_without_loss(value: str) -> None:
    """STRING is length-prefixed, so it must survive any length including empty."""
    encoded = _v1_enc_string(value)
    assert isinstance(encoded, (bytes, bytearray))
    if value:
        assert len(encoded) > 0


@pytest.mark.parametrize("value", [b"", b"\x00", b"\xff" * 100, bytes(range(256))])
def test_xstrings_encode_without_loss(value: bytes) -> None:
    encoded = _v1_enc_xstring(value)
    assert isinstance(encoded, (bytes, bytearray))


# --------------------------------------------------------------------------- #
# wRFC message builders
# --------------------------------------------------------------------------- #


def _logon(**overrides: object) -> tuple[bytes, bytes]:
    from saprfclib.connection import _build_ws_logon_message

    kwargs: dict[str, object] = {
        "func_name": "RFCPING",
        "user": "DEVELOPER",
        "passwd": "s3cr3t-passw0rd",
        "client": "001",
    }
    kwargs.update(overrides)
    return _build_ws_logon_message(**kwargs)  # type: ignore[arg-type]


def test_logon_message_builds_with_a_session_key() -> None:
    message, key = _logon()
    assert len(message) > 0
    assert len(key) > 0


def test_the_password_never_appears_in_the_frame_as_plaintext() -> None:
    """It is scrambled on the wire, as on the classic path.

    Asserted rather than assumed: a refactor that dropped the scrambling would
    still authenticate successfully against a server, so nothing would fail — the
    credential would simply start travelling in clear text inside the TLS tunnel,
    and end up in any capture taken with the TLS keys.
    """
    secret = "s3cr3t-passw0rd"
    message, _ = _logon(passwd=secret)
    assert secret.encode("ascii") not in message
    assert secret.encode("utf-16-le") not in message
    assert secret.upper().encode("utf-16-le") not in message


def test_the_password_still_reaches_the_frame() -> None:
    """The complement of the test above: scrambled, not omitted.

    Checking only that the plaintext is absent would pass just as well if the
    password were dropped entirely, which would be a far worse bug.
    """
    a, _ = _logon(passwd="password-one")
    b, _ = _logon(passwd="password-two")
    assert a != b, "the password must affect the frame"


def test_the_user_and_client_reach_the_frame() -> None:
    a, _ = _logon(user="ALICE")
    b, _ = _logon(user="BOB")
    assert a != b
    c, _ = _logon(client="001")
    d, _ = _logon(client="100")
    assert c != d


def test_an_over_long_function_name_is_refused_by_the_builder() -> None:
    """The guard has to hold at the entry point, not only in the helper."""
    with pytest.raises(ValueError, match="characters"):
        _logon(func_name="F" * 31)


def test_invoke_message_builds_for_a_simple_parameter() -> None:
    from saprfclib.codec import RFCTYPE_CHAR
    from saprfclib.connection import _build_ws_invoke_message
    from saprfclib.types import RFC_IMPORT, FieldDesc, FunctionDesc

    desc = FunctionDesc(
        name="Z_F",
        parameters=[
            FieldDesc(
                name="IV_TEXT",
                rfctype=RFCTYPE_CHAR,
                nuc_length=10,
                nuc_offset=0,
                uc_length=20,
                uc_offset=0,
                decimals=0,
                direction=RFC_IMPORT,
            )
        ],
    )
    short = _build_ws_invoke_message("Z_F", desc, {"IV_TEXT": "hi"})
    long_ = _build_ws_invoke_message("Z_F", desc, {"IV_TEXT": "hello there"})
    assert len(short) > 0

    # The invoke path is length-prefixed, not blank-padded to the field width, so
    # the frame size follows the value. That differs from _v1_encode_char_value,
    # which pads — both forms appear in this module and both are pcap-sourced, so
    # the difference is recorded rather than "corrected" on a guess.
    assert b"C\x04\x00h\x00i\x00E" in short, "short value is length-prefixed, unpadded"

    # Truncation at the declared width does happen, and is the half that matters:
    # uc_length is 20 bytes, so an 11-character value is cut to 10 characters.
    assert b"\x14\x00" in long_, "over-long value is cut to the declared width"
    assert "hello ther".encode("utf-16-le") in long_
    assert "hello there".encode("utf-16-le") not in long_
