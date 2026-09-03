# SPDX-License-Identifier: MPL-2.0
"""wRFC (ngrfc V1) value encoding.

Pure byte-building — no socket, no live system — but it was almost entirely
uncovered because the only tests that reached it were integration tests needing
a WebSocket RFC endpoint. Every field here is fixed-width, which in this codebase
has been the reliable place to find silent corruption.
"""

from __future__ import annotations

import pytest

from saprfclib.connection import (
    _MAX_FUNC_NAME_LEN,
    _pad_call_name,
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


# --------------------------------------------------------------------------- #
# Variable-length values
# --------------------------------------------------------------------------- #


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


def test_logon_message_builds_and_returns_no_session_token() -> None:
    """The second return value is empty now, and that is the point.

    It used to be a 16-byte token for the 0x0514 record. That record is no longer
    sent: a reference client's value is host-derived rather than random, so
    filling it with random bytes put something there no server has been observed
    to accept, and a LOGON without the record at all is confirmed accepted.

    This asserted len(key) > 0, which would have passed just as well for a token
    that was wrong -- it only ever checked that something was produced.
    """
    message, token = _logon()
    assert len(message) > 0
    assert token == b""


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
