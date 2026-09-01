# SPDX-License-Identifier: MPL-2.0
"""Fixed-width wire fields fed by variable-length input.

Four bugs of this exact shape were found in one session, so the class is
searched deliberately rather than stumbled into. Two mechanisms produce it:

  * assigning to a fixed `bytearray` slice — a wrong length silently RESIZES the
    buffer instead of raising, so the frame's total length changes;
  * `.ljust(n)` — a MINIMUM width, not a fixed one, so an over-long input passes
    straight through.

Both are invisible whenever the value that happened to be captured was the right
length, which is why each survived a byte-exact golden test.
"""

from __future__ import annotations

import pytest

from saprfclib.connection import Connection
from saprfclib.server_session import ServerSession
from saprfclib.session import Session


def test_bytearray_slice_assignment_resizes_rather_than_raising() -> None:
    """The language behaviour behind all four bugs, pinned so it is not forgotten."""
    buf = bytearray(8)
    buf[2:6] = b"AB"  # three bytes short of the field
    assert len(buf) == 6, "a short assignment shrinks the buffer, it does not raise"

    buf = bytearray(8)
    buf[2:6] = b"ABCDEFGH"
    assert len(buf) == 12, "a long assignment grows the buffer, it does not raise"


def test_ljust_is_a_minimum_not_a_fixed_width() -> None:
    """The other half of the class."""
    assert len(b"toolongvalue".ljust(4)) == 12, "ljust never truncates"
    assert len(b"toolongvalue"[:4].ljust(4)) == 4, "slicing first is what fixes it"


# --------------------------------------------------------------------------- #
# The specific fields
# --------------------------------------------------------------------------- #


def test_ni_version_request_length_is_stable_across_client_ips() -> None:
    baseline = len(Session().start(local_ip="127.0.0.1"))
    for value in ("1.2.3", "1.2.3.4.5", "999.1.1.1", "", None, "not an ip"):
        assert len(Session().start(local_ip=value)) == baseline


def test_gw_connect_frame_length_is_stable_and_sysnr_is_bounded() -> None:
    baseline = len(Connection._build_gw_connect_request("10.0.0.1", 0, snc=False))
    for sysnr in (0, 42, 99):
        frame = Connection._build_gw_connect_request("10.0.0.1", sysnr, snc=False)
        assert len(frame) == baseline
        assert frame[64:72] == f"sapdp{sysnr:02d} ".encode()
    for bad in (100, 999, -1):
        with pytest.raises(ValueError, match="outside 0-99"):
            Connection._build_gw_connect_request("10.0.0.1", bad, snc=False)


def test_gw_connect_frame_length_is_stable_across_host_lengths() -> None:
    """A long hostname must not change the frame size."""
    baseline = len(Connection._build_gw_connect_request("10.0.0.1", 0, snc=False))
    for host in ("a", "a" * 8, "a" * 50, "a" * 111, "a" * 300):
        assert len(Connection._build_gw_connect_request(host, 0, snc=False)) == baseline


def test_post_registration_frame_length_is_stable() -> None:
    session = ServerSession()
    for host in ("10.0.0.1", "a" * 128):
        assert len(session.build_post_reg_a(host)) == 224
    with pytest.raises(ValueError, match="reserves"):
        session.build_post_reg_a("a" * 129)


def test_program_id_is_truncated_at_the_field_width_not_at_eight() -> None:
    """A 16-byte field was being cut to 8.

    Invisible in the capture it was written from, which used the seven-character
    program ID "python3" — slicing at 8 changed nothing there. Any longer ID
    registered under half its name, and a gateway that cannot match the SM59
    destination simply never sends the server a call. Nothing reports it.
    """
    for prog_id, expected in [
        ("python3", b"python3         "),
        ("SAPRFC_TEST", b"SAPRFC_TEST     "),
        ("MY_RFC_SERVER", b"MY_RFC_SERVER   "),
        ("A" * 20, b"A" * 16),
    ]:
        field = prog_id.encode("ascii")[:16].ljust(16, b"\x20")
        assert len(field) == 16
        assert field == expected


def test_the_ni_init_capture_still_reproduces() -> None:
    """The fix must not disturb the frame the capture recorded.

    "python3" is exactly the value for which the old and new code agree, which is
    both why the bug survived and why this fixture cannot detect it — noted here
    so nobody reads a passing fixture as proof the field is right.
    """
    from pathlib import Path

    capture = (
        Path(__file__).parent / "golden" / "framing" / "server_ni_init_client.bin"
    ).read_bytes()
    assert capture[0x2A:0x3A] == b"python3         "
    assert b"python3"[:16].ljust(16, b"\x20") == capture[0x2A:0x3A]
