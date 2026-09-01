# SPDX-License-Identifier: MPL-2.0
"""A non-Unicode connection is refused rather than decoded wrongly.

SAP ended support for non-Unicode systems with NetWeaver 7.5, so they are out of
scope here. That decision alone would not justify a hard refusal -- an unsupported
configuration can usually be left to work or not work on its own. This one cannot,
because of how ``unicode_mode`` is spent downstream.

It is *derived* as one thing::

    unicode_mode = codepage == "4103"      # "the wire is UTF-16LE"

and *used* as another::

    return "utf-16-le" if field.unicode_mode else "utf-16-be"   # codec.py

Those are different questions. False means "not UTF-16LE", which on a genuinely
non-Unicode system means single-byte text -- and the codec would then decode it as
UTF-16BE. Not fail: decode, into mojibake, in every character field of every call.
The connection would look healthy the whole time.

So the handshake refuses instead. The refusal is scoped to live connections: an
offline descriptor built without a negotiated codepage has unicode_mode false by
construction rather than by observation, and must keep working.
"""

from __future__ import annotations

import struct

import pytest

from saprfclib.session import Session


def _session_at_logon(codepage: str) -> Session:
    s = Session()
    s._codepage = codepage
    return s


def test_a_non_unicode_codepage_is_refused_and_names_itself() -> None:
    """1100 is Latin-1: single-byte, and the case that would produce mojibake."""
    session = _session_at_logon("1100")
    gw = struct.pack(">H", session._GW_RFC_TYPE) + b"\x00" * (session._GW_RFC_PREAMBLE - 2)
    with pytest.raises(ValueError) as excinfo:
        session._handle_logon_response(gw + struct.pack(">HH", 0xFFFF, 0))
    message = str(excinfo.value)
    assert "1100" in message, "the caller must be told which codepage was refused"
    assert "4103" in message, "and which one is required"
    assert "Non-Unicode" in message


def test_the_unicode_codepage_is_accepted() -> None:
    """The control: 4103 must still go through, or the guard is useless."""
    session = _session_at_logon("4103")
    gw = struct.pack(">H", session._GW_RFC_TYPE) + b"\x00" * (session._GW_RFC_PREAMBLE - 2)
    session._handle_logon_response(gw + struct.pack(">HH", 0xFFFF, 0))
    assert session.attributes is not None
    assert session.attributes.unicode_mode is True


def test_an_offline_session_without_a_codepage_is_not_refused() -> None:
    """Mock and offline paths negotiate nothing; refusing them would break them.

    The guard keys on a codepage actually being present, so "no codepage" and
    "a codepage that is not 4103" stay distinguishable. Conflating them would
    turn every offline test into a refusal.
    """
    session = _session_at_logon("")
    session._handle_logon_response(struct.pack(">HH", 0xFFFF, 0))
    assert session.attributes is not None
    assert session.attributes.unicode_mode is False


def test_the_conflation_that_makes_this_necessary_is_real() -> None:
    """Pins the downstream behaviour the refusal exists to prevent.

    If this ever stops being true -- if the codec learns to pick a charset from
    the codepage rather than from a bool -- the refusal could be softened. Until
    then it is load-bearing, and this test is what says so.
    """
    from saprfclib.codec import _uc_encoding
    from saprfclib.types import RFC_IMPORT, FieldDesc

    def _field(unicode_mode: bool) -> FieldDesc:
        return FieldDesc(
            name="F",
            rfctype=0,
            nuc_length=1,
            nuc_offset=0,
            uc_length=2,
            uc_offset=0,
            decimals=0,
            unicode_mode=unicode_mode,
            direction=RFC_IMPORT,
        )

    assert _uc_encoding(_field(True)) == "utf-16-le"
    # Not "single byte" -- a two-byte codec, applied to what would be
    # single-byte text. That is the silent corruption, in one line.
    assert _uc_encoding(_field(False)) == "utf-16-be"
