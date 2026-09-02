# SPDX-License-Identifier: MPL-2.0
"""The wRFC LOGON frame, rebuilt to a shape a server actually accepts (#14).

Established by replaying a reference client's LOGON from this library's own
transport. It was accepted, which localised the whole fault to the frame -- the
HTTP upgrade, the WebSocket layer and the TLS were never the problem. Then one
field at a time was substituted into that accepted frame:

    program name 0x0130    accepted -- free
    function name 0x0102   accepted -- free
    session token 0x0514   accepted when removed entirely -- optional
    password 0x0117        REFUSED, "Name or password is incorrect"

So the shape is right and only the credential encoding had to be worked out. The
password field is 17 bytes for a 13-character password: a 4-byte seed and a
13-byte body. Thirteen is odd, so the body cannot be UTF-16 at all.

These tests pin the shape rather than the bytes. The reference frame is not
committed -- it carries the capturing user's live password material -- so what is
asserted here is structure, widths and encoding, which is what a future change
would break.
"""

from __future__ import annotations

import struct

import pytest

from saprfclib.connection import _build_ws_logon_message, _scramble_password_ws

# Tag order as observed in an accepted LOGON.
EXPECTED_TAGS = [
    0x0101,
    0x0103,
    0x0106,
    0x0514,
    0x0114,
    0x0111,
    0x0117,
    0x0115,
    0x0501,
    0x0007,
    0x0011,
    0x0012,
    0x0013,
    0x0008,
    0x0006,
    0x0130,
    0x0502,
    0x000B,
    0x0102,
    0xFFFF,
]


def _records(b: bytes) -> list[tuple[int, bytes]]:
    out, pos, n = [], 0, len(b)
    while pos + 4 <= n:
        tag, ln = struct.unpack_from(">HH", b, pos)
        pos += 4
        if tag == 0xFFFF:
            out.append((tag, b""))
            break
        if ln == 0xFFFF:
            ln = struct.unpack_from(">I", b, pos)[0]
            pos += 4
        val = b[pos : pos + ln]
        pos += ln
        if pos + 2 <= n and struct.unpack_from(">H", b, pos)[0] == tag:
            pos += 2
        out.append((tag, val))
    return out


def _logon(**kw: object) -> bytes:
    args: dict[str, object] = {
        "func_name": "RFCPING",
        "user": "DEVELOPER",
        "passwd": "secret",
        "client": "001",
        "lang": "E",
        "local_ip": "127.0.0.1",
        "server_host": "example.invalid",
        "server_port": 443,
    }
    args.update(kw)
    msg, _token = _build_ws_logon_message(**args)  # type: ignore[arg-type]
    return msg


def test_the_record_set_matches_an_accepted_logon() -> None:
    assert [t for t, _ in _records(_logon())] == EXPECTED_TAGS


def test_there_is_no_ngrfc_record() -> None:
    """The single defect that made every wRFC session fail.

    A 0x5001 record tells the server to receive RFC data for the call named in
    the frame. There is none to receive, so it answers
    CALL_FUNCTION_RECEIVE_ERROR -- which is what "error when receiving data for
    an RFC" means, read literally.
    """
    assert 0x5001 not in [t for t, _ in _records(_logon())]


def test_requests_are_single_byte_not_utf16() -> None:
    """The wire is asymmetric: requests single-byte, responses UTF-16LE.

    Encoding the request as UTF-16 doubles every string, which is most of why
    the old frame was ~1040 bytes against a working 238.
    """
    by_tag = dict(_records(_logon(client="001", lang="E", func_name="RFCPING")))
    assert by_tag[0x0114] == b"001"  # 3 bytes, not 6
    assert by_tag[0x0115] == b"E"  # 1 byte, not 2
    assert by_tag[0x0102] == b"RFCPING"  # 7 bytes, not 14


def test_the_password_field_width_follows_the_password_length() -> None:
    """4-byte seed plus one byte per character.

    A 13-character password gives 17 bytes, matching an accepted frame. Under the
    old UTF-16 encoding it gave 30, and the server answered "Name or password is
    incorrect" -- an error about the credential that says nothing about the
    encoding being the cause.
    """
    for pw, expected in (("x", 5), ("secret", 10), ("thirteenchars", 17)):
        assert len(_scramble_password_ws(pw, seed=1)) == expected


def test_the_password_is_not_sent_in_clear() -> None:
    frame = _logon(passwd="Sup3rSecret!")
    assert b"Sup3rSecret!" not in frame
    assert "Sup3rSecret!".encode("utf-16-le") not in frame


def test_the_password_still_reaches_the_frame() -> None:
    """Absent would also satisfy 'not in clear', and would be far worse."""
    assert _logon(passwd="password-one") != _logon(passwd="password-two")


def test_fields_confirmed_free_are_settable() -> None:
    """0x0130 and 0x0102 were substituted into an accepted frame and stayed accepted."""
    by_tag = dict(_records(_logon(prog_name="saprfclib", func_name="RFC_PING")))
    assert by_tag[0x0130] == b"saprfclib"
    assert by_tag[0x0102] == b"RFC_PING"


def test_the_session_token_is_returned_for_correlation() -> None:
    """16 bytes, generated here and echoed in the reply.

    Removing it entirely is also accepted -- the reply then omits it too, which is
    how it was established the client proposes it rather than the server issuing
    it.
    """
    msg, token = _build_ws_logon_message(
        func_name="RFCPING",
        user="U",
        passwd="p",
        client="001",
        lang="E",
        server_host="example.invalid",
        server_port=443,
    )
    assert len(token) == 16
    assert dict(_records(msg))[0x0514] == token


def test_an_over_long_function_name_is_refused() -> None:
    """The old builder rejected these as a side effect of padding.

    This shape sends the name unpadded, so the check is deliberate now. A name
    truncated on the wire would invoke a different function than the caller asked
    for, which is worse than an error.
    """
    with pytest.raises(ValueError, match="30"):
        _logon(func_name="F" * 31)


def test_a_password_that_cannot_be_encoded_fails_loudly() -> None:
    """latin-1 raises rather than substituting.

    Silently replacing a character would authenticate as a different credential
    than the caller supplied, and the failure would look like a wrong password.
    """
    with pytest.raises(UnicodeEncodeError):
        _scramble_password_ws("pass中word", seed=1)
