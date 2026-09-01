# SPDX-License-Identifier: MPL-2.0
"""A wRFC LOGON reply can authenticate and fail at the same time.

Captured on A4H kernel 793. The reply to a LOGON carrying an embedded RFCPING is
1118 bytes and contains both halves at once::

    0x0450 'A4H'  0x0452 '00'  0x0453 'vhcala4hci'      <- auth, filled in
    0x0418 ';W=SAPLSYSU,E=163,H=3,N=3;S=RFCPING,...'    <- ABAP call stack
    0x0415 '00'   0x0416 'X'   0x0417 '341'
    0x0403 'CALL_FUNCTION_RECEIVE_ERROR'
    0x0402 'Error when receiving data for an RFC.'

The auth tags are populated whether or not the embedded call ran, so a reader
that checks only for a sys_id sees a clean logon. That is what the library did:
declared the session ready, sent an invoke into it, and the work process took a
short dump -- which came back as a WebSocket close reading
``RABAX_STATE:Error when receiving data for an RFC.``

The ``163`` in issue #14 lives in the 0x0418 breadcrumb. It had been hardcoded at
two sites and used as a fallback at a third, never read. A constant that happens
to be correct is still a defect: it reports 163 for failures that are not 163.
"""

from __future__ import annotations

from pathlib import Path

from saprfclib.connection import _ws_logon_failure, _ws_parse_logon_response

FIXTURE = Path(__file__).parent / "golden" / "framing" / "wrfc_logon_receive_error.bin"


def test_the_reply_authenticates_which_is_why_the_failure_was_missed() -> None:
    """Both halves are true at once; that is the whole trap."""
    attrs = _ws_parse_logon_response(FIXTURE.read_bytes())
    assert attrs is not None
    assert attrs.sys_id == "A4H"
    assert attrs.sys_number == "00"
    assert attrs.kernel_rel == "793"


def test_the_embedded_call_failure_is_detected() -> None:
    failure = _ws_logon_failure(FIXTURE.read_bytes())
    assert failure is not None
    assert failure.msg_class == "00"
    assert failure.msg_type == "X"  # short dump / abort
    assert failure.msg_number == "341"


def test_the_e_code_is_read_from_the_breadcrumb_not_assumed() -> None:
    """163 comes out of 0x0418, where the server put it.

    The point is not the value -- it is that the value now has a source. A
    hardcoded 163 reports 163 for every failure, including the ones that are not.
    """
    text = str(_ws_logon_failure(FIXTURE.read_bytes()))
    assert "163" in text
    assert "CALL_FUNCTION_RECEIVE_ERROR" in text
    assert "Error when receiving data for an RFC." in text


def test_a_reply_without_an_exception_yields_none() -> None:
    """Otherwise every successful logon would raise.

    None and a failure have to stay distinguishable, or the fix for reading an
    error as success becomes reading a success as error.
    """
    import struct

    from saprfclib.invoke import tlv_record as tr

    clean = (
        tr(0x0450, "A4H".encode("utf-16-le"))
        + tr(0x0452, "00".encode("utf-16-le"))
        + struct.pack(">HH", 0xFFFF, 0)
    )
    assert _ws_logon_failure(clean) is None


def test_both_logon_paths_check_for_the_embedded_failure() -> None:
    """The fix was applied to one call site first and needed to be at both.

    _call_bootstrap raises the failure; _ws_direct_logon_call falls back to
    classic TCP. Different responses, same precondition -- and the direct path is
    where missing it costs the most, because it would go on to send an invoke
    into a dead session and provoke an ABAP short dump on the server for every
    connection attempt.

    Asserted structurally rather than behaviourally: exercising either path needs
    a live WebSocket endpoint, and a check that silently stops being called is
    exactly what this is guarding against.
    """
    import inspect

    from saprfclib import connection

    for name in ("_call_bootstrap", "_ws_direct_logon_call"):
        src = inspect.getsource(getattr(connection.Connection, name))
        if "_ws_parse_logon_response" not in src:
            continue
        assert "_ws_logon_failure" in src, (
            f"{name} parses a wRFC LOGON reply without checking whether it carries "
            f"an embedded failure"
        )
