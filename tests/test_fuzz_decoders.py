# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Property and fuzz tests for the decoders that read what the peer sends (#88).

Three properties, applied to each decoder that can have them:

1. **Round trip.** ``decode(encode(x)) == x`` over the legal range, including the
   length boundaries where an encoding changes form (a TLV record switches to the
   extended length at 0xFFFF bytes).
2. **Arbitrary chunking.** A valid byte stream delivered in arbitrary pieces, as TCP
   may deliver it, gives the same messages as the whole stream at once.
3. **Hostile bytes.** Any input either decodes, waits for more data, or raises the
   decoder's typed error (``ValueError``, or a ``SapRfcError`` subclass where the
   layer reports a peer's refusal). Never ``IndexError``, ``struct.error``,
   ``KeyError``, ``UnicodeDecodeError`` or anything else a caller cannot catch on
   purpose.

Hostile inputs are mostly mutations of the golden corpus (``tests/golden/**/*.bin``):
real frames with bytes flipped, inserted, deleted, truncated, or overwritten with
the length values that change how a length is read. Pure random bytes rarely get
past the first length check; a mutated real frame gets deep into the decoder.

The packed-BCD round trip is in ``tests/test_codec_bcd_precision.py``; this file adds
only the hostile-bytes property for it.
"""

from __future__ import annotations

import asyncio
import struct
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from saprfclib import SapRfcError, router
from saprfclib.codec import RFCTYPE_BCD, decode
from saprfclib.invoke import (
    _iter_tlv_records,
    _parse_tlv_stream,
    parse_cpic_error,
    parse_gateway_error,
    parse_invoke_response,
    tlv_record,
)
from saprfclib.session import Session, SessionState
from saprfclib.transport import AsyncTransport, Transport, build_ni_frame
from saprfclib.types import FieldDesc

from .test_connection import _stfc_desc
from .test_invoke import _stfc_connection_desc
from .test_table_params import _basxml_desc, _nested_desc, _read_table_desc, _sxpg_desc

GOLDEN = Path(__file__).parent / "golden"
CORPUS = {p.relative_to(GOLDEN).as_posix(): p.read_bytes() for p in sorted(GOLDEN.rglob("*.bin"))}
RESPONSES = {k: v for k, v in CORPUS.items() if "response" in k or "reply" in k}
HANDSHAKE = {k: v for k, v in CORPUS.items() if k.startswith("handshake/")}
ROUTER = {k: v for k, v in CORPUS.items() if k.startswith("router/")}

FAST = settings(max_examples=150, deadline=None)

# Length values that change how a length field is read, written over two bytes.
_LENGTH_EDGES = [b"\xff\xff", b"\x00\x00", b"\xff\xfe", b"\x7f\xff", b"\x00\x01"]


@st.composite
def _mutated(draw: Any, pool: dict[str, bytes]) -> bytes:
    data = bytearray(draw(st.sampled_from(sorted(pool.values()))))
    for _ in range(draw(st.integers(min_value=0, max_value=4))):
        op = draw(st.sampled_from(["flip", "insert", "delete", "truncate", "edge"]))
        at = draw(st.integers(min_value=0, max_value=max(len(data), 1))) % (len(data) + 1)
        if op == "flip" and data:
            data[min(at, len(data) - 1)] = draw(st.integers(0, 255))
        elif op == "insert":
            data[at:at] = draw(st.binary(min_size=1, max_size=4))
        elif op == "delete" and data:
            del data[min(at, len(data) - 1)]
        elif op == "truncate":
            del data[at:]
        elif op == "edge" and len(data) >= 2:
            i = min(at, len(data) - 2)
            data[i : i + 2] = draw(st.sampled_from(_LENGTH_EDGES))
    return bytes(data)


def hostile(pool: dict[str, bytes] = CORPUS) -> st.SearchStrategy[bytes]:
    """Mutated golden frames, with some plain random bytes mixed in."""
    return st.one_of(_mutated(pool), st.binary(max_size=128))


# --------------------------------------------------------------------------- #
# NI framing (transport.py)
# --------------------------------------------------------------------------- #


class _ChunkedSocket:
    """A socket double whose recv_into returns at most the next chunk size."""

    def __init__(self, data: bytes, chunks: list[int]) -> None:
        self._data = data
        self._pos = 0
        self._chunks = chunks or [len(data) or 1]
        self._i = 0
        self.requested: list[int] = []

    def recv_into(self, view: memoryview, n: int) -> int:
        self.requested.append(n)
        chunk = self._chunks[self._i % len(self._chunks)]
        self._i += 1
        take = min(n, chunk, len(self._data) - self._pos)
        view[:take] = self._data[self._pos : self._pos + take]
        self._pos += take
        return take


# A payload starting with the router error marker is a refusal, not a message.
_NOT_RTERR = st.binary(max_size=300).filter(lambda b: not b.startswith(b"NI_RTERR"))


@FAST
@given(
    payloads=st.lists(_NOT_RTERR, max_size=5),
    chunks=st.lists(st.integers(min_value=1, max_value=64), max_size=8),
)
def test_ni_frames_read_back_whatever_the_chunking(
    payloads: list[bytes], chunks: list[int]
) -> None:
    stream = b"".join(build_ni_frame(p) for p in payloads)
    transport = Transport(_ChunkedSocket(stream, chunks))  # type: ignore[arg-type]
    assert [transport.recv_message() for _ in payloads] == payloads
    with pytest.raises(EOFError):
        transport.recv_message()


@FAST
@given(stream=hostile(), chunks=st.lists(st.integers(min_value=1, max_value=64), max_size=4))
def test_a_hostile_ni_stream_yields_messages_or_a_typed_error(
    stream: bytes, chunks: list[int]
) -> None:
    transport = Transport(_ChunkedSocket(stream, chunks))  # type: ignore[arg-type]
    with pytest.raises((EOFError, ValueError, SapRfcError)):
        for _ in range(len(stream) + 1):  # every message consumes at least 4 bytes
            transport.recv_message()


def test_an_oversized_ni_length_is_refused_before_its_payload_is_read() -> None:
    sock = _ChunkedSocket(struct.pack(">I", Transport._MAX_FRAME_BYTES + 1) + b"x" * 16, [64])
    with pytest.raises(ValueError, match="DoS guard"):
        Transport(sock).recv_message()  # type: ignore[arg-type]
    assert sum(sock.requested) == 4, "only the length header may be read"


def _async_read(stream: bytes, chunks: list[int], count: int) -> list[bytes]:
    async def main() -> list[bytes]:
        reader = asyncio.StreamReader()
        pos, i = 0, 0
        steps = chunks or [len(stream) or 1]
        while pos < len(stream):
            step = steps[i % len(steps)]
            reader.feed_data(stream[pos : pos + step])
            pos += step
            i += 1
        reader.feed_eof()
        transport = AsyncTransport(reader, None)  # type: ignore[arg-type]
        return [await transport.recv_message() for _ in range(count)]

    return asyncio.run(main())


@settings(max_examples=60, deadline=None)
@given(
    payloads=st.lists(_NOT_RTERR, max_size=4),
    chunks=st.lists(st.integers(min_value=1, max_value=64), max_size=8),
)
def test_async_ni_frames_read_back_whatever_the_chunking(
    payloads: list[bytes], chunks: list[int]
) -> None:
    stream = b"".join(build_ni_frame(p) for p in payloads)
    assert _async_read(stream, chunks, len(payloads)) == payloads
    with pytest.raises(EOFError):  # asyncio.IncompleteReadError is an EOFError
        _async_read(stream, chunks, len(payloads) + 1)


@settings(max_examples=60, deadline=None)
@given(stream=hostile())
def test_a_hostile_async_ni_stream_yields_messages_or_a_typed_error(stream: bytes) -> None:
    with pytest.raises((EOFError, ValueError, SapRfcError)):
        _async_read(stream, [7], len(stream) + 1)


# --------------------------------------------------------------------------- #
# Tag stream (invoke.py, session.py)
# --------------------------------------------------------------------------- #

# Around the switch to the extended length form at 0xFFFF, plus small values.
_BOUNDARY_LENGTHS = st.sampled_from([0, 1, 2, 0xFFFE, 0xFFFF, 0x10000])
_LENGTHS = st.one_of(_BOUNDARY_LENGTHS, st.integers(min_value=0, max_value=40))
_TAGS = st.integers(min_value=0, max_value=0xFFFE)  # 0xFFFF is the terminator


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(_TAGS, _LENGTHS, st.integers(0, 255)), max_size=4))
def test_tag_records_read_back_across_the_extended_length_boundary(
    spec: list[tuple[int, int, int]],
) -> None:
    records = [(tag, bytes([fill]) * length) for tag, length, fill in spec]
    stream = b"".join(tlv_record(t, v) for t, v in records) + struct.pack(">HH", 0xFFFF, 0)
    assert list(_iter_tlv_records(stream)) == records
    assert _parse_tlv_stream(stream) == dict(records)  # last value wins for a repeated tag


@FAST
@given(st.lists(st.tuples(_TAGS, st.binary(max_size=40)), max_size=6))
def test_handshake_tag_records_read_back(records: list[tuple[int, bytes]]) -> None:
    # The handshake parser reads the compact form only: no handshake frame has been
    # seen with a value of 0xFFFF bytes or more.
    stream = b"".join(tlv_record(t, v) for t, v in records) + struct.pack(">HH", 0xFFFF, 0)
    assert Session._parse_tlv(stream) == dict(records)


@st.composite
def _cut_tag_stream(draw: Any) -> bytes:
    """Record headers whose length fields take the edge values, cut at any byte.

    Corpus mutations seldom leave a length field right at the end of the buffer,
    which is where a missing bounds check (a truncated extended length, say) shows.
    """
    out = bytearray()
    for _ in range(draw(st.integers(min_value=1, max_value=4))):
        out += struct.pack(">H", draw(_TAGS))
        out += draw(st.sampled_from(_LENGTH_EDGES + [b"\x00\x03"]))
        out += draw(st.binary(max_size=8))
    return bytes(out[: draw(st.integers(min_value=0, max_value=len(out)))])


@FAST
@given(st.one_of(hostile(RESPONSES), _cut_tag_stream()))
def test_a_hostile_tag_stream_raises_only_value_error(data: bytes) -> None:
    for parse in (lambda d: list(_iter_tlv_records(d)), _parse_tlv_stream, Session._parse_tlv):
        try:
            parse(data)
        except ValueError:
            pass


_DESCS = [_read_table_desc(), _basxml_desc(), _nested_desc(), _sxpg_desc()]
_DESCS += [_stfc_connection_desc(), _stfc_desc()]


@settings(max_examples=300, deadline=None)
@given(data=hostile(RESPONSES), desc=st.sampled_from(_DESCS), skip_gw=st.booleans())
def test_a_hostile_response_raises_only_value_error_or_an_rfc_error(
    data: bytes, desc: Any, skip_gw: bool
) -> None:
    # A decompression failure inside a table is reported as ValueError
    # (invoke.decompress_table_stream), so DecompressError is not part of this contract.
    if skip_gw and len(data) > 80:
        data = data[80:]  # the TLV stream after the gateway header
    try:
        parse_invoke_response(data, desc)
    except (ValueError, SapRfcError):
        pass


# --------------------------------------------------------------------------- #
# Gateway header, CPIC, handshake replies
# --------------------------------------------------------------------------- #


@FAST
@given(hostile())
def test_gateway_and_cpic_error_readers_never_raise(data: bytes) -> None:
    for read in (parse_gateway_error, parse_cpic_error):
        text = read(data)
        assert text is None or isinstance(text, str)


_HANDSHAKE_STATES = [
    SessionState.CONNECTED,
    SessionState.NI_VERSIONED,
    SessionState.GW_CONNECTED,
    SessionState.GW_DONE,
]


@settings(max_examples=200, deadline=None)
@given(data=hostile(HANDSHAKE | RESPONSES), state=st.sampled_from(_HANDSHAKE_STATES))
def test_a_hostile_handshake_reply_raises_only_typed_errors(
    data: bytes, state: SessionState
) -> None:
    session = Session()
    session._state = state
    try:
        session.feed(data)
    except (ValueError, SapRfcError):
        pass


# --------------------------------------------------------------------------- #
# Packed BCD (codec.py)
# --------------------------------------------------------------------------- #


@FAST
@given(raw=st.binary(min_size=1, max_size=16), decimals=st.integers(min_value=0, max_value=14))
def test_packed_bytes_decode_to_a_decimal_or_raise_value_error(raw: bytes, decimals: int) -> None:
    field = FieldDesc(
        name="P",
        rfctype=RFCTYPE_BCD,
        nuc_length=len(raw),
        nuc_offset=0,
        uc_length=len(raw),
        uc_offset=0,
        decimals=decimals,
    )
    try:
        value = decode(RFCTYPE_BCD, raw, field)
    except ValueError:
        return
    assert isinstance(value, Decimal)


# --------------------------------------------------------------------------- #
# SAProuter route strings and message server replies (router.py)
# --------------------------------------------------------------------------- #

_ROUTES = [
    "/H/saprouter.example/S/3299/W/secret/H/10.0.0.5/S/3300",
    "/H/a/H/b",
    "/H/host/S/sapgw00",
]


@st.composite
def _route_text(draw: Any) -> str:
    chars = list(draw(st.sampled_from(_ROUTES)))
    for _ in range(draw(st.integers(min_value=0, max_value=4))):
        at = draw(st.integers(min_value=0, max_value=len(chars)))
        piece = draw(st.sampled_from(list("/HSWP0123456789abc.:- ")))
        if draw(st.booleans()) and chars:
            chars[min(at, len(chars) - 1)] = piece
        else:
            chars.insert(at, piece)
    return "".join(chars)


@FAST
@given(st.one_of(_route_text(), st.text(max_size=60)))
def test_a_route_string_parses_or_raises_value_error(route: str) -> None:
    try:
        hops = router.parse_route_string(route)
    except (ValueError, SapRfcError):
        return
    assert all(isinstance(h, router.RouteHop) for h in hops)


_MS_PARSERS = [
    router.parse_sapms_server_list,
    router.parse_ms_list_reply,
    router.parse_sapms_reply,
    router.decode_ms_errorno,
]


@settings(max_examples=200, deadline=None)
@given(data=hostile(ROUTER), parse=st.sampled_from(_MS_PARSERS), with_ni_prefix=st.booleans())
def test_a_hostile_message_server_reply_raises_only_typed_errors(
    data: bytes, parse: Any, with_ni_prefix: bool
) -> None:
    if with_ni_prefix:
        data = struct.pack(">I", len(data)) + data
    try:
        parse(data)
    except (ValueError, SapRfcError):
        pass


@FAST
@given(st.text(max_size=200))
def test_message_server_http_lists_never_raise(body: str) -> None:
    assert isinstance(router.parse_ms_http_logon(body), list)
    assert isinstance(router.parse_ms_http_lglist(body), list)


_MS_NAME = st.text(
    alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), min_size=1, max_size=40
)


@FAST
@given(toname=_MS_NAME, fromname=_MS_NAME, msgtype=st.integers(min_value=0, max_value=255))
def test_a_sapms_frame_reads_back(toname: str, fromname: str, msgtype: int) -> None:
    frame = router.build_sapms_frame(
        operation=0x08, toname=toname, fromname=fromname, msgtype=msgtype
    )
    assert router.parse_sapms_reply(frame) == (0, toname, fromname, msgtype)
    # The same, as delivered with the NI length prefix in front.
    assert router.parse_sapms_reply(struct.pack(">I", len(frame)) + frame)[1:] == (
        toname,
        fromname,
        msgtype,
    )
