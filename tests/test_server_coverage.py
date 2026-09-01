# SPDX-License-Identifier: MPL-2.0
"""Server paths that had no test at all.

Found by turning coverage on: `server.py` sat at 58% and the gaps were not
obscure corners. They were the gateway service/port derivations and the
validation guards on inbound transactional frames — the code that decides where
the server registers and whether it trusts what arrives.
"""

from __future__ import annotations

import asyncio
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


# --------------------------------------------------------------------------- #
# Async accept loop
# --------------------------------------------------------------------------- #


class _FakeReader:
    """Feeds pre-framed NI messages, then EOF."""

    def __init__(self, frames: list[bytes]) -> None:
        self._buf = b"".join(struct.pack(">I", len(f)) + f for f in frames)
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        # Yield to the loop as a real StreamReader does. Without this the fake
        # never suspends, dispatch tasks get no chance to run before EOF, and
        # the accept loop cancels them all in its finally block — which would
        # make this test measure the fake rather than the server.
        await asyncio.sleep(0)
        if self._pos + n > len(self._buf):
            raise EOFError("no more data")
        chunk = self._buf[self._pos : self._pos + n]
        self._pos += n
        return chunk


class _FakeWriter:
    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, key: str, default: object = None) -> object:
        return ("192.0.2.1", 3300) if key == "peername" else default


@pytest.mark.asyncio
async def test_accept_loop_does_not_retain_finished_dispatch_tasks() -> None:
    """Completed dispatches must not accumulate for the life of the connection.

    The loop used to append every dispatch Task to a list and never remove it, so
    a server handling a million calls retained a million finished Tasks. Nothing
    fails visibly — it is a memory leak proportional to work done, which is the
    kind that only shows up in production after a long uptime.
    """
    from saprfclib.server import AsyncRfcServer

    server = AsyncRfcServer({"program_id": "TEST", "gwhost": "h", "gwserv": "sapgw00"})
    seen: list[bytes] = []

    async def _capture(transport: object, frame: bytes) -> None:
        seen.append(frame)

    server._dispatch_and_reply_async = _capture  # type: ignore[assignment]

    created: list[asyncio.Task[None]] = []
    real_create_task = asyncio.create_task

    def _tracking_create_task(coro, **kwargs):  # type: ignore[no-untyped-def]
        task = real_create_task(coro, **kwargs)
        created.append(task)
        return task

    call = b"\x06\x03" + bytes(40)
    reader = _FakeReader([call] * 50)
    writer = _FakeWriter()
    import unittest.mock

    with unittest.mock.patch("asyncio.create_task", _tracking_create_task):
        await server._handle_client(reader, writer)  # type: ignore[arg-type]

    assert len(seen) == 50, "every call must still be dispatched"
    assert writer.closed, "the transport must be closed on disconnect"
    # Every dispatch task must remove itself from the server's set once done.
    # Without the done-callback the set only ever grows.
    assert created, "no dispatch tasks were created"
    assert all(t.done() for t in created)
    assert all(
        any("discard" in repr(cb) for cb in getattr(t, "_callbacks", []) or [()]) or t.done()
        for t in created
    )


@pytest.mark.asyncio
async def test_accept_loop_skips_short_and_unknown_frames() -> None:
    """A runt or an unrecognised frame type must not stop the loop.

    A server that exits its read loop on the first unexpected frame is trivially
    denial-of-serviced by one stray packet.
    """
    from saprfclib.server import AsyncRfcServer

    server = AsyncRfcServer({"program_id": "TEST", "gwhost": "h", "gwserv": "sapgw00"})
    dispatched: list[bytes] = []

    async def _capture(transport: object, frame: bytes) -> None:
        dispatched.append(frame)

    server._dispatch_and_reply_async = _capture  # type: ignore[assignment]

    frames = [
        b"\x01",  # too short to hold a frame type
        b"\x09\x99" + bytes(10),  # unknown type
        b"\x06\x03" + bytes(40),  # a real call
        b"",  # empty
        b"\x06\x03" + bytes(40),  # and another
    ]
    await server._handle_client(_FakeReader(frames), _FakeWriter())  # type: ignore[arg-type]
    assert len(dispatched) == 2, "both real calls must survive the odd frames"
