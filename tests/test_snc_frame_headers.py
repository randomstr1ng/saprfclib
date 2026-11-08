# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""SNC frame headers against the reference client (golden snc_frame_headers.json).

Covers the handshake QOP field and how the server's minimum raises the level in
use, the data-frame type that level selects, the extension header, and the GW
envelope differences between handshake and data frames.
"""

import json
import pathlib
import struct

import pytest

from saprfclib.exceptions import SncError
from saprfclib.snc import (
    SncFrameType,
    SncTransport,
    _build_snc_ext_header,
    build_snc_frame,
    parse_snc_frame,
)

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "snc" / "snc_frame_headers.json").read_text()
)
_EYE = b"SNCFRAME"


class _Mech:
    """GSS mechanism double: two handshake rounds, identity wrap/MIC."""

    _real = False
    _lib = None

    def __init__(self):
        self._step = 0

    def init_sec_context(self, token):
        self._step += 1
        return (1, b"tok%d" % self._step) if self._step < 3 else (0, b"")

    def wrap(self, payload):
        return b"W" + payload

    def unwrap(self, token):
        return token[1:]

    def get_mic(self, payload):
        return b"MIC"

    def verify_mic(self, payload, mic):
        assert mic == b"MIC"

    def close(self):
        pass


class _Inner:
    def __init__(self, inbound):
        self.sent: list[bytes] = []
        self._in = list(inbound)

    def send_message(self, b):
        self.sent.append(b)

    def recv_message(self):
        return self._in.pop(0)

    def close(self):
        pass


def _accept(qop):
    return build_snc_frame(_EYE, int(SncFrameType.FR_ACCEPT), 3, qop, gss_token=b"srv")


def _gw(frame):
    return b"\x06\xcb" + b"\x00" * 78 + frame


def _transport(
    snc_qop, server_qop, *, gw=False, conn_idx=None, extra_inbound=(), handle=b"86792311"
):
    inbound = [_accept(server_qop), _accept(server_qop)]
    if gw:
        inbound = [_gw(f) for f in inbound]
    inner = _Inner([*inbound, *extra_inbound])
    t = SncTransport(
        inner,
        snc_partnername=FX["partner_name"],
        snc_qop=snc_qop,
        gss_binding=_Mech(),
    )
    t.activate_snc(gw_handle=handle if gw else None, conn_idx=conn_idx)
    return t, inner


def _hdr_qop(snc_header_hex):
    return struct.unpack(">H", bytes.fromhex(snc_header_hex)[0x16:0x18])[0]


@pytest.mark.parametrize("q", [1, 2, 3, 8, 9])
def test_handshake_qop_fields_match_reference(q):
    rows = FX["by_snc_qop"][f"snc_qop_{q}"]
    want = [_hdr_qop(r["snc_header"]) for r in rows if r["dir"] == "C>S"][:2]
    server = [_hdr_qop(r["snc_header"]) for r in rows if r["dir"] == "S>C"][0]
    _, inner = _transport(q, server)
    got = [parse_snc_frame(f)[2] for f in inner.sent[:2]]
    assert got == want


def test_extension_header_matches_reference():
    first = FX["by_snc_qop"]["snc_qop_3"][0]
    dn = FX["partner_name"][2:]
    assert _build_snc_ext_header(dn).hex() == first["ext_header"]


@pytest.mark.parametrize("q", [1, 2, 3, 8, 9])
def test_server_minimum_raises_level_to_privacy(q):
    # The reference server answers 0x7e (min 3): every snc_qop ends in type-9 data.
    t, inner = _transport(q, 0x7E)
    t.send_message(b"payload")
    ftype, _ctx, qop, tok, data = parse_snc_frame(inner.sent[-1])
    assert ftype == SncFrameType.PRIVACY
    assert qop == 0  # data frames carry 0 in the QOP field
    assert tok == b"Wpayload" and data == b""


@pytest.mark.parametrize(
    "q,ftype", [(1, SncFrameType.PLAIN), (2, SncFrameType.INTEGRITY), (3, SncFrameType.PRIVACY)]
)
def test_permissive_server_keeps_client_level(q, ftype):
    t, inner = _transport(q, 0x3A)  # server min 1, max 3, use 1
    t.send_message(b"payload")
    assert parse_snc_frame(inner.sent[-1])[0] == ftype


def test_frame_below_own_minimum_is_rejected():
    plain = build_snc_frame(_EYE, int(SncFrameType.PLAIN), 3, 0, app_data=b"injected")
    t, _ = _transport(3, 0x7E, extra_inbound=[plain])
    with pytest.raises(SncError, match="minimum"):
        t.recv_message()


def test_low_level_client_accepts_higher_protection():
    wrapped = build_snc_frame(_EYE, int(SncFrameType.PRIVACY), 3, 0, gss_token=b"Wdata")
    t, _ = _transport(1, 0x3A, extra_inbound=[wrapped])
    assert t.recv_message() == b"data"


def test_handshake_frame_after_completion_is_rejected():
    t, _ = _transport(3, 0x7E, extra_inbound=[_accept(0x7E)])
    with pytest.raises(SncError, match="unexpected SNC frame type"):
        t.recv_message()


@pytest.mark.parametrize(
    "bad", [0x00, 0x02, 0x66, 0x1E, 0x76]
)  # min 0 / max 0 / min > use / use > max
def test_invalid_server_qop_is_rejected(bad):
    with pytest.raises(SncError, match="protection level"):
        _transport(3, bad)


def test_gw_envelope_handshake_vs_data_and_connection_index():
    rows = FX["by_snc_qop"]["snc_qop_3"]
    ref_hs = bytes.fromhex(rows[0]["gw_header"])
    ref_data = bytes.fromhex(next(r for r in rows if r["snc_header"][16:18] == "09")["gw_header"])
    t, inner = _transport(
        3, 0x7E, gw=True, conn_idx=struct.unpack(">H", ref_hs[78:80])[0], handle=ref_hs[40:48]
    )
    t.send_message(b"payload")
    hs, data = inner.sent[0], inner.sent[-1]
    assert hs[40:48] == ref_hs[40:48]
    for lo, hi in ((0, 3), (4, 6), (10, 11), (26, 28), (30, 32), (76, 80)):
        assert hs[lo:hi] == ref_hs[lo:hi], (lo, hi)
    # The reference's first data frame reuses a receive buffer, so [76:78] and a few
    # other bytes hold leftovers from the server header; compare the defined fields.
    for lo, hi in ((0, 3), (4, 6), (10, 11), (26, 28), (30, 32), (78, 80)):
        assert data[lo:hi] == ref_data[lo:hi], (lo, hi)
    assert data[76:78] == b"\xff\xff"
    assert hs[48:52] == ref_hs[48:52] == b"\x00\x00\x85\x00"
    assert data[48:52] == b"\x00\x00\x00\x00"
    assert hs[10] == 0x28 and data[10] == 0x08
    # trailer: BE32 SNC frame length + 00 00 85 00 on client frames
    assert hs[-4:] == bytes.fromhex(rows[0]["trailer"])[-4:]
    assert struct.unpack(">I", hs[-8:-4])[0] == len(hs) - 88


def test_connection_index_observed_values():
    for runs in FX["connection_index"].values():
        for conn in runs:
            ack = bytes.fromhex(conn[1]["bytes_76_80"])
            assert conn[1]["dir"] == "S>C"
            for later in conn[2:]:
                assert bytes.fromhex(later["bytes_76_80"]) == b"\xff\xff" + ack[2:4]


@pytest.mark.parametrize(
    "name,ok",
    [
        ("CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE", True),
        ("CN=a_b, C=de", True),  # T61String for '_', C upper-cased
        ("CN=Müller, C=DE", False),  # non-ASCII: refused, server acceptance untested
        ("E=x@y, C=DE", False),
    ],
)
def test_partner_dn_encoding(name, ok):
    if ok:
        hdr = _build_snc_ext_header(name)
        if "a_b" in name:
            assert b"\x14\x03a_b" in hdr and b"\x13\x02DE" in hdr
    else:
        with pytest.raises(ValueError):
            _build_snc_ext_header(name)


# --- logon records: snc_sso vs password logon ---------------------------------

LOGON = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "snc" / "snc_logon_tlvs.json").read_text()
)


def _tags(tlv: bytes) -> list[str]:
    out, i = [], 0
    while i + 4 <= len(tlv):
        t = int.from_bytes(tlv[i : i + 2], "big")
        n = int.from_bytes(tlv[i + 2 : i + 4], "big")
        out.append(f"{t:04x}")
        if t == 0xFFFF:
            break
        i += 4 + n + 2  # extended format repeats the tag after the value
    return out


@pytest.mark.parametrize(
    "mode,user,passwd,pw_logon",
    [
        ("nosso", "U", "pw", True),
        ("sso_nouser", None, None, False),
        ("sso_user", "U", None, False),
    ],
)
def test_logon_records_match_reference(mode, user, passwd, pw_logon):
    from saprfclib.connection import Connection

    tlv = Connection._build_logon_request(
        client="001", user=user, passwd=passwd, seed=1, snc_password_logon=pw_logon
    )
    assert _tags(tlv) == LOGON["modes"][mode]["tags"][1:]  # [0] is the COM header


def test_snc_sso_drops_the_password(monkeypatch, caplog):
    import saprfclib

    seen = {}

    def _boom(*a, **k):
        seen.update(k)
        raise RuntimeError("stop")

    monkeypatch.setattr("saprfclib.connection._builtin_snc_mechanism", _boom)
    with pytest.raises(RuntimeError, match="stop"):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            user="U",
            passwd="SECRET-PW",
            snc_partnername="p:CN=X",
            snc_pse="x.pse",
            snc_sso=True,
        )
    assert "SECRET-PW" not in caplog.text
    assert "password is ignored" in caplog.text


def test_snc_sso_without_snc_is_rejected():
    import saprfclib

    with pytest.raises(ValueError, match="snc_sso"):
        saprfclib.connect(ashost="h", sysnr="00", client="001", snc_sso=True)


def _logon_reply(**fields):
    from saprfclib.connection import _tlv_ext
    from saprfclib.session import _TAG_SYS_ID, _TAG_USER

    tags = {_TAG_SYS_ID: fields["sys_id"], _TAG_USER: fields["user"]}
    body = b"".join(_tlv_ext(t, v.encode("utf-16-le")) for t, v in tags.items())
    return body + b"\xff\xff\x00\x00"


@pytest.mark.parametrize("stripped,expected", [(True, "A4H"), (False, "A\x004\x00H")])
def test_logon_reply_without_gw_header_decodes_utf16_only_when_flagged(stripped, expected):
    from saprfclib.session import Session

    s = Session()
    s._codepage = "4103"
    s.gw_header_stripped = stripped
    s._handle_logon_response(_logon_reply(sys_id="A4H", user="DEVELOPER"))
    assert s.attributes.sys_id == expected
    if stripped:
        assert s.attributes.user == "DEVELOPER"
