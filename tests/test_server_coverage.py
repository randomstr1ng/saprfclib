# SPDX-License-Identifier: MPL-2.0
"""Server paths that had no test at all.

Found by turning coverage on: `server.py` sat at 58% and the gaps were not
obscure corners. They were the gateway service/port derivations and the
validation guards on inbound transactional frames — the code that decides where
the server registers and whether it trusts what arrives.
"""

from __future__ import annotations

import struct

import pytest

from saprfclib.invoke import _parse_tlv_stream, build_trfc_request
from saprfclib.server import (
    _TAG_RETURN_CODE,
    RfcServer,
    _dispatcher_svc_8,
    _gwserv_port,
    _scan_5001_char_values,
)


def _server() -> RfcServer:
    return RfcServer({"program_id": "TEST", "gwhost": "localhost", "gwserv": "sapgw00"})


def _rc(response: bytes) -> int:
    raw = _parse_tlv_stream(response).get(_TAG_RETURN_CODE)
    assert raw is not None
    return int(struct.unpack(">I", raw)[0])


# --------------------------------------------------------------------------- #
# Gateway service resolution
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("gwserv", "port"),
    [("sapgw00", 3300), ("sapgw01", 3301), ("sapgw42", 3342), ("sapgw99", 3399), ("3300", 3300)],
)
def test_gateway_service_resolves_to_the_documented_port(gwserv: str, port: int) -> None:
    """sapgw<NN> = 33<NN>, range 3300-3399, per SAP's published port table."""
    assert _gwserv_port(gwserv) == port


@pytest.mark.parametrize("gwserv", ["sapgwfoo", "sapgw", "sapgw-5", "sapgw 1", "sapgw1x"])
def test_an_unreadable_gateway_service_is_refused_not_defaulted(gwserv: str) -> None:
    """These each used to return 3300, silently.

    A server that registers against the wrong gateway reports no error at all —
    it simply never receives the calls it is waiting for, which looks like the
    caller's problem rather than a misconfiguration here.
    """
    with pytest.raises(ValueError, match="instance number|outside"):
        _gwserv_port(gwserv)


def test_an_out_of_range_instance_is_refused() -> None:
    """sapgw999 used to compute 4299 — a port that is not a gateway."""
    with pytest.raises(ValueError, match="outside 0-99"):
        _gwserv_port("sapgw999")
    # 4299 is what the old arithmetic produced; make sure nothing returns it.
    assert _gwserv_port("sapgw99") == 3399


def test_an_unknown_service_name_is_refused() -> None:
    with pytest.raises(ValueError, match="neither a sapgwNN name"):
        _gwserv_port("definitely_not_a_service_name_xyz")


# --------------------------------------------------------------------------- #
# Dispatcher service name — REGISTER_TP carries sapdp, not sapgw
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("gwserv", "expected"),
    [
        ("sapgw00", b"sapdp00 "),
        ("sapgw07", b"sapdp07 "),
        ("3300", b"sapdp00 "),
        ("3342", b"sapdp42 "),
    ],
)
def test_dispatcher_name_is_derived_from_the_instance(gwserv: str, expected: bytes) -> None:
    got = _dispatcher_svc_8(gwserv)
    assert got == expected
    assert len(got) == 8, "REGISTER_TP[64:72] is a fixed 8-byte field"


def test_the_snc_gateway_port_maps_to_the_right_dispatcher() -> None:
    """4800 is the SNC gateway for instance 00, documented as 48<NN>.

    Taking port-3300 unconditionally made that instance 1500 and produced
    "sapdp150" — a truncated name for a dispatcher that does not exist.
    """
    assert _dispatcher_svc_8("4800") == b"sapdp00 "
    assert _dispatcher_svc_8("4842") == b"sapdp42 "


def test_a_port_in_neither_gateway_range_is_refused() -> None:
    with pytest.raises(ValueError, match="neither documented range"):
        _dispatcher_svc_8("9999")


# --------------------------------------------------------------------------- #
# Inbound 0x5001 scanning — a trust boundary
# --------------------------------------------------------------------------- #


def test_scanner_never_reads_past_the_buffer() -> None:
    """A declared length longer than the data must be ignored, not trusted.

    This parses a frame from the network, so a length field that overruns is the
    first thing an attacker reaches for.
    """
    # 0x43, declared length 200, marker 0x80, but only 4 bytes follow.
    truncated = bytes([0x43, 200, 0x80]) + b"ABCD"
    assert _scan_5001_char_values(truncated) == []

    # Exactly-fitting value is accepted.
    exact = bytes([0x43, 4, 0x80]) + b"ABCD"
    assert _scan_5001_char_values(exact) == [(0, 4, b"ABCD")]


def test_scanner_handles_empty_and_tiny_inputs() -> None:
    for data in (b"", b"\x43", b"\x43\x04", b"\x43\x04\x80"):
        assert _scan_5001_char_values(data) == []


def test_scanner_skips_past_a_match_so_values_do_not_nest() -> None:
    """A value whose bytes contain 0x43..0x80 must not yield a phantom second hit."""
    inner = bytes([0x43, 1, 0x80, 0x41])
    data = bytes([0x43, len(inner), 0x80]) + inner
    assert _scan_5001_char_values(data) == [(0, 4, inner)]


# --------------------------------------------------------------------------- #
# Inbound tRFC frame validation
# --------------------------------------------------------------------------- #


def _forge_trfc(tid: str) -> bytes:
    """Build an ARFC_DEST_SHIP frame carrying an arbitrary TID.

    build_trfc_request validates the TID and refuses to construct a bad one,
    which is correct for a client — and exactly why it cannot be used here. The
    server must not depend on the peer having used our builder: a hostile or
    simply broken system sends whatever it likes. So the value is patched in
    after the fact.
    """
    valid = "A" * 24
    frame = build_trfc_request(valid, "Z_FUNC")
    return frame.replace(valid.encode("utf-16-le"), tid.encode("utf-16-le"), 1)


def test_a_trfc_frame_without_a_tid_is_refused() -> None:
    """No TID means no deduplication key, so the unit cannot be exactly-once."""
    server = _server()
    server.install_transaction_handlers()
    frame = build_trfc_request("A" * 24, "Z_FUNC")
    # Blank the TID characters, leaving the frame otherwise intact.
    blanked = frame.replace(("A" * 24).encode("utf-16-le"), (" " * 24).encode("utf-16-le"), 1)
    assert _rc(server.dispatch_inbound(blanked)) != 0


@pytest.mark.parametrize("tid", ["A" * 23 + " ", "A" * 12 + " " * 12])
def test_a_trfc_tid_of_the_wrong_length_is_refused(tid: str) -> None:
    """24 characters exactly. A short TID would collide across transactions.

    Padded to the original width on purpose. Shortening the string would shift
    every TLV length after it and the frame would be rejected as malformed —
    a real rejection, but not the one under test.
    """
    server = _server()
    server.install_transaction_handlers()
    assert _rc(server.dispatch_inbound(_forge_trfc(tid))) != 0


def test_a_trfc_tid_outside_the_alphabet_is_refused() -> None:
    """TIDs are uppercase hex. Anything else did not come from a SAP system.

    The TID reaches a durable store keyed by it, so an unvalidated one is a value
    from the network used as an identifier — worth refusing on its own terms.
    """
    server = _server()
    server.install_transaction_handlers()
    assert _rc(server.dispatch_inbound(_forge_trfc("../../etc/passwd" + "AAAAAAAA"))) != 0
    assert _rc(server.dispatch_inbound(_forge_trfc("A" * 23 + "\x00"))) != 0
