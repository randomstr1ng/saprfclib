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


def test_ni_init_long_program_id_matches_sdk_capture() -> None:
    """A program ID over 8 characters must leave payload[46:54] blank (issue #58).

    Releases up to 0.1.8 wrote program_id[:16] across [38:54]. The only capture
    then available used "python3", for which 8 and 16 agree. The SDK capture with
    "ZFTNT_SIGTEST" shows program_id[:8] then blanks, and the gateway closes the
    handle on any non-blank value there.
    """
    from pathlib import Path

    from saprfclib.server import _build_ni_init

    capture = (
        Path(__file__).parent / "golden" / "framing" / "server_ni_init_client_long_progid.bin"
    ).read_bytes()[4:]
    built = _build_ni_init(capture[2:6], "titan", "ZFTNT_SIGTEST")
    assert built == capture


def test_ni_init_body_matches_the_client_capture() -> None:
    """The client NI init shares the body layout; only [0:2] differs (0203 vs 020b).

    Short program name "python3", where every truncation width agrees — but it pins
    the NUL padding of the process name at [10:20].
    """
    from pathlib import Path

    from saprfclib.server import _build_ni_init

    capture = (
        Path(__file__).parent / "golden" / "framing" / "client_ni_init_request.bin"
    ).read_bytes()[4:]
    built = _build_ni_init(capture[2:6], "titan", "python3")
    assert capture[0:2] == b"\x02\x03"
    assert built[0:2] == b"\x02\x0b"
    assert built[2:] == capture[2:]


@pytest.mark.parametrize("prog_id", ["A", "python3", "ZFTNT_SIGTEST", "A" * 64])
def test_ni_init_length_is_stable_and_tail_blank(prog_id: str) -> None:
    from saprfclib.server import _build_ni_init

    frame = _build_ni_init(b"\x0a\x00\x00\x01", "a" * 50, prog_id)
    assert len(frame) == 64
    assert frame[46:54] == b"\x20" * 8


def test_post_registration_gw_frames_match_sdk_capture() -> None:
    from pathlib import Path

    from saprfclib.server import _build_post_call_d2, _build_reg_waiting

    golden = Path(__file__).parent / "golden" / "framing"

    def load(name: str) -> bytes:
        return (golden / f"{name}.bin").read_bytes()[4:]

    assert _build_reg_waiting() == load("server_reg_waiting")
    done = load("server_dispatch_done")
    assert _build_post_call_d2(done[40:48]) == done
