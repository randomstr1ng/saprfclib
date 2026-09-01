# SPDX-License-Identifier: MPL-2.0
"""Message variables V1-V4, and the free-text tag that turned out not to exist.

Two labels in invoke.py, both closed by one purpose-built exception on A4H
kernel 793::

    MESSAGE e398(00) WITH 'ALPHA1' 'BRAVO2' 'CHARLIE3' 'DELTA4'
            RAISING four_variables.

The four values are distinct deliberately. Four copies of one string would have
parsed identically with the tags in any order and proved nothing. Message 398 of
class 00 was read from T100 as ``'& & & &'`` rather than assumed -- message 001
is ``'&1&2&3&4&5&6&7&8'`` and would have run the values together with no
separator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from saprfclib.exceptions import AbapApplicationError
from saprfclib.invoke import parse_invoke_response
from saprfclib.types import FunctionDesc

GOLDEN = Path(__file__).parent / "golden" / "framing"
FIXTURE = GOLDEN / "exception_msg_variables_response.bin"


def _raise_from_fixture() -> AbapApplicationError:
    body = FIXTURE.read_bytes()[80:]
    with pytest.raises(AbapApplicationError) as excinfo:
        parse_invoke_response(body, FunctionDesc(name="Z_SAPRFCLIB_MSGVARS", parameters=[]))
    return excinfo.value


def test_each_variable_lands_in_its_own_consecutive_tag() -> None:
    """0x0411-0x0414, confirmed rather than inferred from 0x0411 alone."""
    exc = _raise_from_fixture()
    assert exc.msg_v1 == "ALPHA1"
    assert exc.msg_v2 == "BRAVO2"
    assert exc.msg_v3 == "CHARLIE3"
    assert exc.msg_v4 == "DELTA4"
    assert (exc.key, exc.msg_class, exc.msg_type, exc.msg_number) == (
        "FOUR_VARIABLES",
        "00",
        "E",
        "398",
    )


def test_kernel_793_sends_no_assembled_message_text() -> None:
    """Which is why 0x040B is gone, and why the diagnostic had to change.

    This reply carries a real four-variable message, so it is exactly the frame
    that would populate a free-text tag if one existed. Neither 0x040B -- never
    seen in any capture, yet tried FIRST -- nor 0x0402, which is confirmed on
    kernel 752, appears. The sentence is the client's to assemble from T100, and
    this library does not make that lookup.
    """
    exc = _raise_from_fixture()
    assert exc.message is None


def test_the_diagnostic_string_carries_what_the_server_actually_sent() -> None:
    """Reporting bare 'FOUR_VARIABLES' threw away the only informative part.

    With no free text, the variables are all a caller gets. Holding ALPHA1,
    BRAVO2, CHARLIE3 and DELTA4 on the object while printing none of them made
    the common case on this kernel look like an error with no detail.
    """
    text = str(_raise_from_fixture())
    assert "FOUR_VARIABLES" in text
    assert "00/398" in text
    for value in ("ALPHA1", "BRAVO2", "CHARLIE3", "DELTA4"):
        assert value in text, f"{value} was sent by the server and must not be dropped"


def test_a_free_text_message_still_wins_when_the_server_sends_one() -> None:
    """The 752 shape must not regress into the variable-listing form.

    When the server does assemble the sentence, that sentence is the message and
    the diagnostic stays 'key: message' exactly as before.
    """
    body = (GOLDEN / "signon_incomplete_752_response.bin").read_bytes()[80:]
    with pytest.raises(AbapApplicationError) as excinfo:
        parse_invoke_response(body, FunctionDesc(name="RFC_PING", parameters=[]))
    exc = excinfo.value
    assert exc.message == "Logon data incomplete."
    assert str(exc) == "CALL_FUNCTION_SIGNON_INCOMPL: Logon data incomplete."
