# SPDX-License-Identifier: MPL-2.0
"""RFC trace files in the SDK's format (#21).

The point of matching the format is diffability: comparing an SDK trace against
this library's traffic is what identified every defect behind #14, and doing it
then required parsing the SDK's output by hand because there was nothing on this
side to compare with.

The redaction is the part worth testing hardest. A level-4 SDK trace dumps the
LOGON frame verbatim, and that frame carries tag 0x0117 -- the password
scrambled with a seed that travels beside it. Obfuscation, not encryption: the
capture scripts written during #14 scrub SDK traces before copying them for
exactly this reason. Producing files with the same property under an
official-looking name would be handing users a footgun.
"""

from __future__ import annotations

import struct
from pathlib import Path

from saprfclib.invoke import tlv_record as tr
from saprfclib.trace import TRACE_BRIEF, TRACE_FULL, RfcTrace, redact


def _logon_like(password_material: bytes) -> bytes:
    return (
        tr(0x0102, b"RFCPING")
        + tr(0x0117, password_material)
        + tr(0x0114, b"001")
        + struct.pack(">HH", 0xFFFF, 0)
    )


def test_the_password_is_zeroed_and_the_length_kept() -> None:
    """Length matters as much as the zeroing.

    A redaction that shortened the record would shift every offset after it, and
    the dump exists to be compared with a real frame byte for byte. It would also
    quietly turn a valid record stream into a malformed one.
    """
    secret = bytes.fromhex("1223ab239df652186ab83448e64724ff15")
    frame = _logon_like(secret)
    safe = redact(frame)

    assert len(safe) == len(frame)
    assert secret not in safe
    assert b"\x00" * len(secret) in safe
    # Everything else survives untouched.
    assert b"RFCPING" in safe
    assert b"001" in safe


def test_redaction_reaches_inside_a_gw_framed_payload() -> None:
    """Classic frames carry an 80-byte header before the records.

    Walking from offset zero would find no records at all and silently redact
    nothing -- leaving the credential in the file while the code looked like it
    had done its job.
    """
    secret = b"\xde\xad\xbe\xef" * 4
    frame = b"\x06\xcb" + b"\x00" * 78 + _logon_like(secret)
    safe = redact(frame)
    assert len(safe) == len(frame)
    assert secret not in safe


def test_an_unrecognisable_payload_is_left_alone() -> None:
    """Guessing at offsets could blank real data and still miss a credential."""
    junk = b"\xc6\xd9\xc5\xc5" + bytes(range(60))
    assert redact(junk) == junk


def test_a_trace_file_carries_no_password(tmp_path: Path) -> None:
    """End to end, which is the property that actually matters to a user."""
    secret = bytes.fromhex("1223ab239df652186ab83448e64724ff15")
    path = tmp_path / "rfc_test.trc"
    with RfcTrace(str(path), level=TRACE_FULL) as t:
        t.log("API RfcOpenConnection")
        t.frame("Writing", _logon_like(secret))

    text = path.read_text(encoding="utf-8")
    assert secret.hex().upper()[:16] not in text.replace(" ", "")
    assert "REDACTED" in text, "the header must say the file is redacted"


def test_the_dump_layout_matches_the_sdk(tmp_path: Path) -> None:
    """OFFSET | four hex groups |ASCII| -- so the two files diff line for line."""
    path = tmp_path / "rfc_layout.trc"
    with RfcTrace(str(path), level=TRACE_FULL) as t:
        t.frame("Read", bytes(range(16)))

    dump = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.startswith("000000")]
    assert dump, "no hexdump line written"
    assert dump[0] == "000000 | 00010203 04050607 08090A0B 0C0D0E0F |................|"


def test_level_gates_what_is_written(tmp_path: Path) -> None:
    """A brief trace must not carry frame contents.

    Someone lowering the level to reduce noise is also reducing what leaves the
    process; silently dumping frames anyway would defeat that.
    """
    path = tmp_path / "rfc_brief.trc"
    with RfcTrace(str(path), level=TRACE_BRIEF) as t:
        t.log("API RfcOpenConnection")
        t.frame("Writing", _logon_like(b"\x01\x02\x03\x04"))

    text = path.read_text(encoding="utf-8")
    assert "RfcOpenConnection" in text
    assert "HEXDUMP" not in text


def test_close_is_idempotent(tmp_path: Path) -> None:
    """Cleanup runs on paths that may already have closed it."""
    t = RfcTrace(str(tmp_path / "rfc_close.trc"))
    t.close()
    t.close()
    t.log("after close")  # must not raise


def test_the_transport_writes_what_actually_crossed_the_socket(tmp_path: Path) -> None:
    """The hook sits at the transport, not higher up.

    A trace taken above the transport records what some layer intended to send.
    The whole value of this file is comparing it against an SDK trace of the same
    exchange, and that comparison is only sound if both record the wire.
    """
    import socket as _socket

    from saprfclib.transport import Transport

    a, b = _socket.socketpair()
    try:
        path = tmp_path / "rfc_wire.trc"
        with RfcTrace(str(path), level=TRACE_FULL) as t:
            sender = Transport(a, trace=t)
            receiver = Transport(b, trace=t)
            sender.send_message(_logon_like(b"\xaa" * 8))
            receiver.recv_message()

        text = path.read_text(encoding="utf-8")
        assert "Writing" in text and "Read" in text
        assert text.count(">> HEXDUMP") == 2
        # And the credential is gone from both directions, not just the send.
        assert "AAAAAAAA" not in text.replace(" ", "")
    finally:
        a.close()
        b.close()


def test_a_transport_without_a_trace_is_unaffected() -> None:
    """Tracing is opt-in and must cost nothing when it is off."""
    import socket as _socket

    from saprfclib.transport import Transport

    a, b = _socket.socketpair()
    try:
        sender, receiver = Transport(a), Transport(b)
        assert sender.trace is None
        sender.send_message(b"\x05\x00\x00\x00")
        assert receiver.recv_message() == b"\x05\x00\x00\x00"
    finally:
        a.close()
        b.close()


def test_connect_accepts_a_trace_and_hands_it_to_the_transport(tmp_path: Path) -> None:
    """The writer is useless if a caller cannot turn it on.

    #21 asked for three things: the format, a writer, and a way to enable it.
    The first two can be built and tested in isolation, which is exactly how the
    third came to be missing -- everything passed while the feature was
    unreachable from the public API.
    """
    import saprfclib
    from saprfclib import connection as connection_mod

    # connection.py imports connect_tcp into its own namespace, so patching the
    # transport module would leave the real one in place and the spy would never
    # be called -- an empty capture that looks exactly like the failure it is
    # meant to detect.
    captured: dict[str, object] = {}
    real = connection_mod.connect_tcp

    def spy(host: str, port: int, **kw: object) -> object:
        captured.update(kw)
        raise OSError("probe stops here; the argument has been observed")

    connection_mod.connect_tcp = spy  # type: ignore[assignment]
    try:
        trace = RfcTrace(str(tmp_path / "rfc_connect.trc"))
        try:
            saprfclib.connect(
                ashost="example.invalid",
                sysnr=0,
                client="001",
                user="U",
                passwd="p",
                trace=trace,
            )
        except Exception:
            pass  # the connection is not the point; the argument is
        finally:
            trace.close()
    finally:
        connection_mod.connect_tcp = real  # type: ignore[assignment]

    assert captured.get("trace") is not None, (
        "connect(trace=...) did not reach the transport, so tracing cannot be "
        "switched on by a caller"
    )


def test_no_environment_variable_switches_tracing_on() -> None:
    """Deliberately unlike the SDK, which reads RFC_TRACE from the environment.

    A process that starts writing traffic to disk because of a variable it
    inherited is a surprise, and the file -- credential-redacted though it is --
    still holds everything else that crossed the wire. Enabling it should be
    visible at the call site.
    """
    import saprfclib.trace as trace_mod

    source = Path(trace_mod.__file__).read_text(encoding="utf-8")
    assert "environ" not in source
    assert "getenv" not in source
