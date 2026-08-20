# tests/test_snc_frame.py
#
# Unit tests for the SNC 0x18-byte frame codec (D-02) and SncError.
#
# All tests are offline — the frame codec is pure struct/bytes plumbing.
# Coverage:
#   - build_snc_frame / parse_snc_frame round-trip (fields identical in/out).
#   - Hypothesis round-trip over frame_type/ctx_id/qop and arbitrary token/data.
#   - header inspection: version byte == 6, hdrlen field == 0x18 (D-02).
#   - parse rejects a non-0x18 hdrlen with NotImplementedError (D-23: extension
#     headers not reverse-engineered).
#   - parse rejects an oversized token_len+data_len with ValueError BEFORE
#     slicing (DoS guard, threat T-07-FRAME-DOS / T-03-DOS parity).
#   - SncError carries only GSS major/minor; str() leaks no token/credential.

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib.exceptions import SncError
from saprfclib.snc import (
    SncFrameType,
    SncQop,
    build_snc_frame,
    parse_snc_frame,
)

_EYE = b"SNCPROTO"
_SNC_HEADER_SIZE = 0x18
# Mirror the codec header layout so tests can craft raw frames independently.
_HDR = struct.Struct(">8sBBHIIHH")
_MAX_FRAME_BYTES = 128 * 1024 * 1024


def test_build_parse_roundtrip_identity() -> None:
    token = b"\x01\x02\x03gss-init-token"
    data = b"application-payload-bytes"
    frame = build_snc_frame(
        _EYE,
        SncFrameType.PRIVACY,
        ctx_id=7,
        qop=SncQop.PRIVACY,
        gss_token=token,
        app_data=data,
    )
    ftype, ctx_id, qop, tok, app = parse_snc_frame(frame)
    assert ftype == SncFrameType.PRIVACY
    assert ctx_id == 7
    assert qop == SncQop.PRIVACY
    assert tok == token
    assert app == data


def test_build_parse_empty_token_and_data() -> None:
    frame = build_snc_frame(_EYE, SncFrameType.FR_INIT, ctx_id=0, qop=1)
    ftype, ctx_id, qop, tok, app = parse_snc_frame(frame)
    assert ftype == SncFrameType.FR_INIT
    assert ctx_id == 0
    assert qop == 1
    assert tok == b""
    assert app == b""


def test_header_version_and_hdrlen_fields() -> None:
    frame = build_snc_frame(_EYE, SncFrameType.INTEGRITY, ctx_id=1, qop=2)
    # D-02: byte 0x09 == protocol version 6; bytes 0x0a-0x0b == 0x0018 hdrlen.
    assert frame[0x09] == 6
    assert frame[0x0A:0x0C] == b"\x00\x18"
    # And the eye-catcher occupies the first 8 bytes.
    assert frame[0:8] == _EYE


@given(
    frame_type=st.integers(min_value=1, max_value=9),
    ctx_id=st.integers(min_value=0, max_value=0xFFFF),
    qop=st.integers(min_value=1, max_value=3),
    gss_token=st.binary(max_size=256),
    app_data=st.binary(max_size=256),
)
def test_snc_frame_roundtrip_property(
    frame_type: int, ctx_id: int, qop: int, gss_token: bytes, app_data: bytes
) -> None:
    frame = build_snc_frame(
        _EYE,
        frame_type,
        ctx_id=ctx_id,
        qop=qop,
        gss_token=gss_token,
        app_data=app_data,
    )
    ftype, ctx, q, tok, data = parse_snc_frame(frame)
    assert ftype == frame_type
    assert ctx == ctx_id
    assert q == qop
    assert tok == gss_token
    assert data == app_data


def test_parse_skips_extension_header_bytes() -> None:
    # D-24: extension headers (hdrlen > 0x18) are now understood. parse skips the
    # extension bytes and starts the GSS token at hdrlen.
    ext = b"\x00" * 8  # 8-byte extension header padding
    hdrlen = _SNC_HEADER_SIZE + len(ext)  # 0x18 + 8 = 0x20
    token = b"gss-tok"
    raw = _HDR.pack(_EYE, 7, 6, hdrlen, len(token), 0, 0, 1) + ext + token
    ftype, ctx_id, qop, tok, app = parse_snc_frame(raw)
    assert ftype == 7
    assert tok == token
    assert app == b""


def test_parse_rejects_oversized_lengths_before_slicing() -> None:
    # DoS guard (T-07-FRAME-DOS): a declared token_len+data_len above the 128 MiB
    # cap must raise ValueError BEFORE any allocation/slicing. Craft a header
    # with an oversized declared length WITHOUT allocating the payload.
    token_len = _MAX_FRAME_BYTES
    data_len = 1024
    bad = _HDR.pack(_EYE, 9, 6, 0x18, token_len, data_len, 0, 0)  # header only
    with pytest.raises(ValueError):
        parse_snc_frame(bad)


def test_snc_error_carries_major_minor_no_leak() -> None:
    e = SncError(major=0x00070000, minor=0x2A)
    assert e.major == 0x00070000
    assert e.minor == 0x2A
    text = str(e)
    # Diagnostic must contain hex status, never token/credential material.
    assert "00070000" in text
    assert "SNCPROTO" not in text
    assert "gss-init-token" not in text
