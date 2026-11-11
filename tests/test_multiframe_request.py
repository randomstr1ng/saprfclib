# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Requests larger than one GW frame (golden framing/multiframe_request_*)."""

import json
import pathlib
import struct

import pytest

from saprfclib.connection import _GW_REQUEST_CHUNK, _gw_request_frames
from saprfclib.snc import SncFrameType, SncTransport, build_snc_frame, parse_snc_frame

G = pathlib.Path(__file__).parent / "golden" / "framing"


def _ni_frames(data: bytes) -> list[bytes]:
    out, i = [], 0
    while i < len(data):
        (n,) = struct.unpack(">I", data[i : i + 4])
        out.append(data[i + 4 : i + 4 + n])
        i += 4 + n
    return out


def test_plain_split_matches_reference_byte_for_byte():
    ref = _ni_frames((G / "multiframe_request_plain_frames.bin").read_bytes())
    tlv = b"".join(f[80:] for f in ref)
    # The single frame this library builds first: 0x06CB header + TLV + footer.
    header = bytearray(ref[0][:80])
    struct.pack_into(">H", header, 0, 0x06CB)
    struct.pack_into(">II", header, 24, 8, 0x050C)
    struct.pack_into(">I", header, 48, 0)
    single = bytes(header) + tlv + struct.pack(">I", len(tlv)) + b"\x00\x00\x85\x00"
    assert _gw_request_frames(single) == ref


@pytest.mark.parametrize("tlv_len,frames", [(27998, 1), (28000, 1), (28001, 3), (56001, 4)])
def test_split_threshold_is_a_28000_byte_tlv_stream(tlv_len, frames):
    header = bytes([0x06, 0xCB]) + bytes(78)
    out = _gw_request_frames(header + bytes(tlv_len) + bytes(8))
    assert len(out) == frames
    if frames > 1:
        assert all(len(f) - 80 <= _GW_REQUEST_CHUNK for f in out)
        assert sum(len(f) - 80 for f in out) == tlv_len  # footer dropped
        assert out[-1][:2] == b"\x06\x09" and len(out[-1]) == 80


class _Mech:
    _real = False
    _lib = None

    def __init__(self):
        self.n = 0

    def init_sec_context(self, token):
        self.n += 1
        return (1, b"t") if self.n < 3 else (0, b"")

    def wrap(self, payload):
        return b"W" * 160 + payload  # 160-byte token overhead, like 28000 -> 28160

    def unwrap(self, token):
        return token

    def get_mic(self, payload):
        return b""

    def verify_mic(self, payload, mic):
        pass

    def close(self):
        pass


class _Inner:
    def __init__(self, inbound):
        self.sent, self._in = [], list(inbound)

    def send_message(self, b):
        self.sent.append(b)

    def recv_message(self):
        return self._in.pop(0)

    def close(self):
        pass


def test_snc_chunked_send_matches_reference_headers():
    ref = json.loads((G / "multiframe_request_snc.json").read_text(encoding="utf-8"))["frames"]
    acc = b"\x06\xcb" + bytes(78) + build_snc_frame(b"SNCFRAME", 4, 3, 0x7E, gss_token=b"s")
    inner = _Inner([acc, acc])
    t = SncTransport(inner, snc_partnername="p:CN=X", gss_binding=_Mech())
    first = bytes.fromhex(ref[0]["gw_header"])
    t.activate_snc(gw_handle=first[40:48], conn_idx=struct.unpack(">H", first[78:80])[0])
    inner.sent.clear()
    sizes = [28000, 28000, 28000, 8160]  # plaintext per chunk -> reference wire lengths
    t.send_chunked(bytes(sum(sizes)), _GW_REQUEST_CHUNK)
    assert [len(f) for f in inner.sent] == [r["wire_length"] for r in ref]
    for ours, r in zip(inner.sent, ref, strict=True):
        want = bytes.fromhex(r["gw_header"])
        for lo, hi in ((0, 12), (24, 32), (40, 52), (76, 80)):
            assert ours[lo:hi] == want[lo:hi], (lo, hi)
        if r["snc_header"]:
            ftype, _ctx, qop, _tok, _data = parse_snc_frame(ours[80:])
            assert ftype == SncFrameType.PRIVACY and qop == 0
            assert ours[80:104] == bytes.fromhex(r["snc_header"])
