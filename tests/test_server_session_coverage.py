# SPDX-License-Identifier: MPL-2.0
"""Server-session state machine: framing guards and post-registration frames.

`server_session.py` was the lowest-covered module at 60%. The gaps were the
frame builders and the guards on inbound gateway data — one side building
fixed-width frames from caller input, the other reading frames from the network.
"""

from __future__ import annotations

import struct

import pytest

from saprfclib.server_session import ServerSession, ServerSessionState


def _listening() -> ServerSession:
    session = ServerSession()
    session._state = ServerSessionState.LISTENING
    return session


# --------------------------------------------------------------------------- #
# build_post_reg_a — a fixed-width frame built from caller input
# --------------------------------------------------------------------------- #


def test_post_reg_a_is_always_224_bytes() -> None:
    session = ServerSession()
    for host in ("10.0.0.1", "2001:db8::dead:beef", "a" * 128):
        assert len(session.build_post_reg_a(host)) == 224


def test_an_over_long_host_is_refused_not_silently_truncated() -> None:
    """Two distinct corruptions used to happen here, neither of them reported.

    Between 129 and 144 characters the padding slice went empty and the host
    overran the trailing zero region, leaving a 224-byte frame with wrong
    content. Past that, assigning to a bytearray slice GROWS it rather than
    raising — a 200-character host produced a 280-byte frame, a length the
    gateway cannot parse at all.
    """
    session = ServerSession()
    for length in (129, 144, 200):
        with pytest.raises(ValueError, match="reserves"):
            session.build_post_reg_a("a" * length)


def test_a_non_ascii_host_is_refused() -> None:
    """The field is fixed-width ASCII; a UnicodeEncodeError here is not actionable."""
    session = ServerSession()
    with pytest.raises(ValueError, match="not ASCII"):
        session.build_post_reg_a("gateway.münchen.example")


def test_post_reg_a_carries_the_host_and_its_length() -> None:
    session = ServerSession()
    host = "192.0.2.55"
    frame = session.build_post_reg_a(host)
    assert frame[0:2] == b"\x06\x0f"
    assert frame[48:56] == host.encode()[:8].ljust(8, b" ")
    assert struct.unpack_from(">I", frame, 56)[0] == len(host)
    assert frame[80 : 80 + len(host)] == host.encode()
    # Everything between the host and the trailing zeros is spaces.
    assert set(frame[80 + len(host) : 208]) == {0x20}
    assert frame[208:224] == bytes(16)


def test_post_reg_b_is_always_80_bytes() -> None:
    session = ServerSession()
    frame = session.build_post_reg_b()
    assert len(frame) == 80
    assert frame[0:2] == b"\x06\x05"
    assert frame[76:78] == b"\xff\xff"


# --------------------------------------------------------------------------- #
# Inbound framing guards — data from the network
# --------------------------------------------------------------------------- #


def test_a_truncated_inbound_frame_is_rejected() -> None:
    """Fewer than 4 bytes cannot even hold the NI length."""
    with pytest.raises(ValueError, match="too short"):
        _listening().feed(b"\x00\x00")


def test_a_lying_ni_length_is_rejected() -> None:
    """The declared length must match what actually arrived.

    A frame claiming more than it carries is the first thing a malformed or
    hostile peer sends; accepting it hands a short buffer to the TLV walkers as
    if it were complete.
    """
    session = _listening()
    with pytest.raises(ValueError, match="NI length"):
        session.feed(struct.pack(">I", 999) + b"short")
    # And one claiming less than it carries.
    session2 = _listening()
    with pytest.raises(ValueError, match="NI length"):
        session2.feed(struct.pack(">I", 1) + b"much longer payload")


def test_a_well_formed_inbound_call_advances_to_in_call() -> None:
    session = _listening()
    payload = b"\x06\x03" + bytes(60)
    assert session.feed(struct.pack(">I", len(payload)) + payload) == payload
    assert session.state is ServerSessionState.IN_CALL


def test_feeding_in_an_unexpected_state_raises() -> None:
    """A state machine that ignores an out-of-order frame loses track quietly."""
    session = ServerSession()
    session._state = ServerSessionState.IN_CALL
    with pytest.raises(ValueError, match="unexpected feed"):
        session.feed(b"\x00\x00\x00\x02ab")


# --------------------------------------------------------------------------- #
# Registration ACK
# --------------------------------------------------------------------------- #


def test_a_short_registration_ack_is_rejected() -> None:
    """The handle lives at [40:48]; a shorter payload cannot contain one."""
    session = ServerSession()
    session._state = ServerSessionState.GW_CONNECTED
    with pytest.raises(ValueError, match="too short"):
        session.feed(bytes(79))


def test_the_registration_ack_handle_is_extracted() -> None:
    session = ServerSession()
    session._state = ServerSessionState.GW_CONNECTED
    ack = bytearray(80)
    ack[0:2] = b"\x06\x01"
    ack[40:48] = b"36964135"
    session.feed(bytes(ack))
    assert session._handle == b"36964135"
    # The handle must then appear in the frames built from it.
    assert session.build_post_reg_b()[40:48] == b"36964135"
