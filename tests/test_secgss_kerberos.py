# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Kerberos key exchange (suite 0x0007) against golden secgss_kerberos_loopback.json.

The fixture is a handshake and record exchange between this initiator and SAP
CommonCryptoLib acting as the acceptor, with a dummy keytab. Replaying it with the
recorded randomness must reproduce every client token byte for byte and accept
every server token.
"""

import datetime as dt
import json
import pathlib

import pytest

from saprfclib.exceptions import SncError
from saprfclib.krb5.client import Credential, Principal
from saprfclib.krb5.crypto import Key
from saprfclib.secgss import GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, SecGssKerberosInitiator

FX = json.loads(
    (pathlib.Path(__file__).parent / "golden" / "snc" / "secgss_kerberos_loopback.json").read_text()
)


def _cred(enctype=18):
    t0 = dt.datetime.fromtimestamp(int(FX["now"]), dt.UTC)
    return Credential(
        client=Principal(("alice",), "EXAMPLE.COM"),
        server=Principal(("svc",), "EXAMPLE.COM"),
        ticket=bytes.fromhex(FX["ticket"]),
        session_key=Key(enctype, bytes.fromhex(FX["session_key"])),
        flags=b"\x40\xe1\x00\x00",
        authtime=t0,
        starttime=t0,
        endtime=t0 + dt.timedelta(hours=10),
        renew_till=None,
    )


def _initiator():
    pool = [bytes.fromhex(r) for r in FX["random"]]

    def rnd(n):
        b = pool.pop(0)
        assert len(b) == n
        return b

    return SecGssKerberosInitiator(_cred(), random=rnd, clock=lambda: FX["now"]), pool


def _handshake():
    ini, pool = _initiator()
    hs = FX["handshake"]
    major, tok1 = ini.init_sec_context(b"")
    assert major == GSS_S_CONTINUE_NEEDED and tok1.hex() == hs[0]["token"]
    major, tok3 = ini.init_sec_context(bytes.fromhex(hs[1]["token"]))
    assert major == GSS_S_COMPLETE and tok3.hex() == hs[2]["token"]
    assert hs[3]["major"] == "0x0" and hs[3]["token"] == ""  # acceptor done, no output
    return ini, pool


def test_handshake_replays_byte_for_byte():
    ini, _ = _handshake()
    assert ini.established


def test_first_token_carries_hello_ticket_and_key_transport():
    tok = bytes.fromhex(FX["handshake"][0]["token"])
    assert bytes.fromhex(FX["ticket"]) in tok
    # ClientHello key-exchange list = 01, extension 3 offers suite 00 07 only.
    assert b"\x01\x01\x01\x01\x01\x01\x02\x01\x02\x01\x02\x01\x01" in tok
    assert b"\x04\x02\x00\x07" in tok


def test_records_replay_against_commoncryptolib():
    ini, pool = _handshake()
    for r in FX["records"]:
        plain = bytes.fromhex(r["plain"])
        token = bytes.fromhex(r["token"])
        if r["op"] == "c_wrap":
            assert ini.wrap(plain) == token and r["ccl_major"] == "0x0"
        elif r["op"] == "s_wrap":
            assert ini.unwrap(token) == plain
        elif r["op"] == "c_mic":
            assert ini.get_mic(plain) == token and r["ccl_major"] == "0x0"
        else:
            ini.verify_mic(plain, token)
    assert pool == []  # every recorded random value consumed, in order


def test_tampered_server_finished_fails_closed():
    ini, _ = _initiator()
    ini.init_sec_context(b"")
    bad = bytearray(bytes.fromhex(FX["handshake"][1]["token"]))
    bad[-1] ^= 1
    with pytest.raises(SncError):
        ini.init_sec_context(bytes(bad))
    with pytest.raises(SncError):
        ini.wrap(b"x")


def test_wrong_session_key_fails_closed():
    # A server that cannot decrypt the ticket cannot produce our pre-master secret:
    # with a different session key on our side the server Finished does not verify.
    pool = [bytes.fromhex(r) for r in FX["random"]]
    cred = _cred()
    other = Credential(**{**cred.__dict__, "session_key": Key(18, bytes(32))})
    ini = SecGssKerberosInitiator(other, random=lambda n: pool.pop(0), clock=lambda: FX["now"])
    ini.init_sec_context(b"")
    with pytest.raises(SncError, match="Finished"):
        ini.init_sec_context(bytes.fromhex(FX["handshake"][1]["token"]))


def test_server_choosing_x509_suite_is_refused():
    ini, _ = _initiator()
    ini.init_sec_context(b"")
    tok = bytearray(bytes.fromhex(FX["handshake"][1]["token"]))
    i = tok.index(bytes.fromhex("01010007"))
    tok[i + 3] = 0x09
    with pytest.raises(SncError, match="cipher suite"):
        ini.init_sec_context(bytes(tok))


def test_rc4_session_key_is_refused():
    with pytest.raises(ValueError):
        Key(23, bytes(16))
