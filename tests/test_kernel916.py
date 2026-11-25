# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Replies from a kernel 916 system (ABAP Platform 2025, SAP_BASIS 816), replayed.

Fixtures: tests/golden/framing/logon_reply_kernel916.{bin,json} and
stfc_connection_response_kernel916.{bin,json}, live captures of saprfclib against
that system. They pin that a newer kernel's replies parse with the existing code, so
a later change that breaks them shows up here rather than on a customer's system.
"""

from __future__ import annotations

import json
import struct

from saprfclib.invoke import parse_invoke_response
from saprfclib.session import Session, SessionState
from tests.conftest import GOLDEN_ROOT
from tests.test_invoke import _stfc_connection_desc
from tests.test_session import _drive_to_logon

FRAMING = GOLDEN_ROOT / "framing"


def _fixture(name: str) -> tuple[bytes, dict]:
    raw = (FRAMING / f"{name}.bin").read_bytes()
    meta = json.loads((FRAMING / f"{name}.json").read_text(encoding="utf-8"))
    assert struct.unpack_from(">I", raw)[0] == len(raw) - 4
    return raw, meta


def _tags(raw: bytes, start: int) -> list[int]:
    out, p = [], start
    while p + 4 <= len(raw):
        tag, length = struct.unpack_from(">HH", raw, p)
        if tag == 0xFFFF:
            break
        out.append(tag)
        p += 4 + length
        if p + 2 <= len(raw) and struct.unpack_from(">H", raw, p)[0] == tag:
            p += 2
    return out


def test_the_kernel_916_logon_reply_reaches_ready_with_its_attributes() -> None:
    raw, meta = _fixture("logon_reply_kernel916")
    sess = Session()
    _drive_to_logon(sess)
    sess.feed(raw[4:])
    assert sess.state is SessionState.READY
    attrs = sess.attributes
    assert attrs is not None
    for name, value in meta["expected_parse"].items():
        assert getattr(attrs, name) == value, name


def test_the_kernel_916_logon_reply_carries_no_new_tags() -> None:
    """Same tags as kernel 793, minus 0x0006; 0x0161 is sent by both."""
    raw, _ = _fixture("logon_reply_kernel916")
    tags = _tags(raw, 84)
    assert 0x0161 in tags
    assert 0x0006 not in tags
    assert 0x0454 not in tags and 0x0527 not in tags
    assert tags[:5] == [0x0101, 0x0103, 0x0106, 0x0161, 0x0016]


def test_the_kernel_916_call_reply_parses() -> None:
    raw, meta = _fixture("stfc_connection_response_kernel916")
    result = parse_invoke_response(raw[4:][80:], _stfc_connection_desc())
    assert result["ECHOTEXT"].rstrip() == meta["expected_parse"]["ECHOTEXT"]
    assert result["RESPTEXT"].startswith(meta["expected_parse"]["RESPTEXT_prefix"])
    assert 0x0527 not in _tags(raw, 84)
