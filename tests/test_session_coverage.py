# SPDX-License-Identifier: MPL-2.0
"""Client session: fixed-width fields and truncated-response guards.

The uncovered branches here were the length guards on each handshake response
and the client_ip field. Both sit on the path every connection takes.
"""

from __future__ import annotations

import pytest

from saprfclib.session import Session, SessionState, _ipv4_octets


def test_the_ni_version_request_is_always_the_same_length() -> None:
    """The client_ip field is fixed-width; a bad value must not resize the frame.

    This is the first frame of every connection. `bytes(...)` succeeds for
    "1.2.3", so the existing except never fired, and assigning three bytes to a
    four-byte slice shrank the bytearray — a 63-byte request instead of 64, and
    65 for a five-octet value.
    """
    baseline = len(Session().start(local_ip="127.0.0.1"))
    assert baseline == 64
    for value in ("10.1.2.3", "1.2.3", "1.2.3.4.5", "999.1.1.1", "not an ip", "", None):
        assert len(Session().start(local_ip=value)) == baseline, f"{value!r} resized the frame"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.1.2.3", bytes((10, 1, 2, 3))),
        ("0.0.0.0", bytes(4)),
        ("255.255.255.255", b"\xff\xff\xff\xff"),
        # Everything unusable falls back to loopback — informational field, so a
        # caller should not fail to connect over it.
        ("1.2.3", bytes((127, 0, 0, 1))),
        ("1.2.3.4.5", bytes((127, 0, 0, 1))),
        ("256.0.0.1", bytes((127, 0, 0, 1))),
        ("-1.0.0.1", bytes((127, 0, 0, 1))),
        ("a.b.c.d", bytes((127, 0, 0, 1))),
        ("", bytes((127, 0, 0, 1))),
        (None, bytes((127, 0, 0, 1))),
    ],
)
def test_ipv4_octets_is_always_four_bytes(value: str | None, expected: bytes) -> None:
    got = _ipv4_octets(value)
    assert len(got) == 4, "the field width is the contract"
    assert got == expected


def test_a_valid_ip_reaches_the_frame() -> None:
    """The fallback must not swallow good input."""
    assert Session().start(local_ip="192.0.2.44")[2:6] == bytes((192, 0, 2, 44))


# --------------------------------------------------------------------------- #
# Truncated server responses
# --------------------------------------------------------------------------- #


def test_a_truncated_ni_version_response_is_rejected() -> None:
    """Short of the codepage offset there is nothing to read; guessing is worse."""
    session = Session()
    session.start(local_ip="127.0.0.1")
    with pytest.raises(ValueError, match="NI version response too short"):
        session.feed(bytes(8))


def test_a_truncated_gw_connect_response_is_rejected() -> None:
    """The connection handle lives at a fixed offset; without it nothing works."""
    session = Session()
    session.start(local_ip="127.0.0.1")
    session._state = SessionState.NI_VERSIONED
    with pytest.raises(ValueError, match="GW connect response too short"):
        session.feed(bytes(16))


def test_a_truncated_gw_done_frame_is_rejected() -> None:
    session = Session()
    session.start(local_ip="127.0.0.1")
    session._state = SessionState.GW_CONNECTED
    with pytest.raises(ValueError, match="GW done frame too short"):
        session.feed(bytes(8))


def test_feeding_in_an_unexpected_state_raises() -> None:
    session = Session()
    session._state = SessionState.READY
    with pytest.raises(ValueError, match="unexpected feed"):
        session.feed(bytes(64))
