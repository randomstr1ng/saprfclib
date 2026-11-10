# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Pure-Python Kerberos: RFC test vectors, MIT file formats, AS/TGS state machines.

The crypto vectors are copied from RFC 3961 Appendix A.1 and RFC 3962 Appendix B.
The keytab and ccache fixtures were written by MIT krb5. The exchange tests drive
the client state machines against a minimal in-test KDC built from the same
message definitions; they check the client's control flow and verification, not
interoperability — that is covered by the live integration test at the bottom.
"""

import datetime as dt
import json
import os
import pathlib

import pytest
from asn1crypto import parser

from saprfclib.krb5 import crypto
from saprfclib.krb5 import messages as m
from saprfclib.krb5.client import (
    AsExchange,
    Credential,
    KerberosError,
    Principal,
    TgsExchange,
    kdc_roundtrip,
)
from saprfclib.krb5.crypto import Key, n_fold, string_to_key
from saprfclib.krb5.files import (
    CredentialCacheError,
    default_ccache_path,
    read_ccache,
    read_keytab,
)

GOLDEN = pathlib.Path(__file__).parent / "golden" / "krb5"
h = bytes.fromhex

# --- RFC 3961 A.1 n-fold -------------------------------------------------------


@pytest.mark.parametrize(
    "data,bits,out",
    [
        (b"012345", 64, "be072631276b1955"),
        (b"password", 56, "78a07b6caf85fa"),
        (b"Rough Consensus, and Running Code", 64, "bb6ed30870b7f0e0"),
        (b"password", 168, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"),
        (
            b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
            192,
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
        ),
        (b"Q", 168, "518a54a215a8452a518a54a215a8452a518a54a215"),
        (b"ba", 168, "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"),
        (b"kerberos", 64, "6b65726265726f73"),
        (b"kerberos", 128, "6b65726265726f737b9b5b2b93132b93"),
        (b"kerberos", 168, "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4"),
        (
            b"kerberos",
            256,
            "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4",
        ),
    ],
)
def test_n_fold(data, bits, out):
    assert n_fold(data, bits // 8).hex() == out


# --- RFC 3962 B string-to-key ----------------------------------------------------

_S2K = [
    (
        1,
        "password",
        b"ATHENA.MIT.EDUraeburn",
        "42263c6e89f4fc28b8df68ee09799f15",
        "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
    ),
    (
        2,
        "password",
        b"ATHENA.MIT.EDUraeburn",
        "c651bf29e2300ac27fa469d693bdda13",
        "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
    ),
    (
        1200,
        "password",
        b"ATHENA.MIT.EDUraeburn",
        "4c01cd46d632d01e6dbe230a01ed642a",
        "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
    ),
    (
        5,
        "password",
        h("1234567878563412"),
        "e9b23d52273747dd5c35cb55be619d8e",
        "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31",
    ),
    (
        1200,
        "X" * 64,
        b"pass phrase equals block size",
        "59d1bb789a828b1aa54ef9c2883f69ed",
        "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
    ),
    (
        1200,
        "X" * 65,
        b"pass phrase exceeds block size",
        "cb8005dc5f90179a7f02104c0018751d",
        "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
    ),
    (
        50,
        h("f09d849e"),
        b"EXAMPLE.COMpianist",
        "f149c1f2e154a73452d43e7fe62a56e5",
        "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
    ),
]


@pytest.mark.parametrize("it,pw,salt,k128,k256", _S2K)
def test_string_to_key(it, pw, salt, k128, k256):
    assert string_to_key(17, pw, salt, it).contents.hex() == k128
    assert string_to_key(18, pw, salt, it).contents.hex() == k256


# --- RFC 3962 B ciphertext stealing ----------------------------------------------

_CTS_KEY = b"chicken teriyaki"
_CTS_IN = b"I would like the General Gau's Chicken, please, and wonton soup."
_CTS = [
    (17, "c6353568f2bf8cb4d8a580362da7ff7f97"),
    (31, "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"),
    (32, "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"),
    (
        47,
        "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e"
        "39312523a78662d5be7fcbcc98ebf5",
    ),
    (
        48,
        "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd8"
        "39312523a78662d5be7fcbcc98ebf5a8",
    ),
    (
        64,
        "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8"
        "4807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
    ),
]


@pytest.mark.parametrize("n,out", _CTS)
def test_cts_vectors(n, out):
    c = crypto._cts_encrypt(_CTS_KEY, _CTS_IN[:n])
    assert c.hex() == out
    assert crypto._cts_decrypt(_CTS_KEY, c) == _CTS_IN[:n]


@pytest.mark.parametrize("enctype", [17, 18])
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 33, 100])
def test_encrypt_roundtrip_and_tamper(enctype, length):
    key = string_to_key(enctype, "pw", "SALT")
    msg = bytes(range(length))
    ct = crypto.encrypt(key, 3, msg)
    assert len(ct) == 16 + length + 12
    assert crypto.decrypt(key, 3, ct) == msg
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt(key, 4, ct)  # wrong key usage
    bad = bytearray(ct)
    bad[0] ^= 1
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt(key, 3, bytes(bad))


def test_checksum_verify():
    key = string_to_key(18, "pw", "SALT")
    ctype, val = crypto.checksum(key, 6, b"body")
    assert ctype == crypto.CKSUMTYPE_HMAC_SHA1_96_AES256 and len(val) == 12
    crypto.verify_checksum(key, 6, b"body", ctype, val)
    with pytest.raises(crypto.IntegrityError):
        crypto.verify_checksum(key, 6, b"bodx", ctype, val)


def test_key_repr_is_redacted():
    k = Key(18, bytes(range(32)))
    assert bytes(range(32)).hex() not in repr(k) and "redacted" in repr(k)
    with pytest.raises(ValueError):
        Key(23, bytes(16))  # RC4 is not implemented


# --- MIT file formats ------------------------------------------------------------


def test_keytab_from_mit_ktutil():
    exp = json.loads((GOLDEN / "mit_keytab_v2.json").read_text())
    entries = read_keytab((GOLDEN / "mit_keytab_v2.keytab").read_bytes())
    assert len(entries) == len(exp["entries"])
    for e, want in zip(entries, exp["entries"], strict=True):
        assert str(e.principal) == want["principal"]
        assert e.principal.name_type == want["name_type"]
        assert (e.kvno, e.enctype) == (want["kvno"], want["enctype"])
        if want["salt"] is None:
            assert e.key is None  # RC4: listed, no usable key
        else:
            assert e.key == string_to_key(e.enctype, exp["password"], want["salt"])


def test_ccache_from_mit():
    exp = json.loads((GOLDEN / "mit_ccache_v4.json").read_text())
    default, creds = read_ccache((GOLDEN / "mit_ccache_v4.ccache").read_bytes())
    assert str(default) == exp["default_principal"]
    assert [(str(c.server), c.session_key.enctype, len(c.ticket)) for c in creds] == [
        (w["server"], w["enctype"], w["ticket_len"]) for w in exp["credentials"]
    ]
    assert all(c.client == default for c in creds)
    assert all(c.endtime > c.authtime for c in creds)


@pytest.mark.parametrize("blob", [b"", b"\x05\x01", b"\x05\x02\x00", b"\x04\x04"])
def test_bad_ccache_rejected(blob):
    with pytest.raises(CredentialCacheError):
        read_ccache(blob)


def test_truncated_ccache_rejected():
    data = (GOLDEN / "mit_ccache_v4.ccache").read_bytes()
    with pytest.raises(CredentialCacheError, match="truncated"):
        read_ccache(data[:-10])


@pytest.mark.parametrize(
    "value,result",
    [
        ("FILE:/tmp/x", "/tmp/x"),
        ("/tmp/y", "/tmp/y"),
        ("KEYRING:persistent:1", None),
        ("KCM:", None),
    ],
)
def test_default_ccache_path(monkeypatch, value, result):
    monkeypatch.setenv("KRB5CCNAME", value)
    if result is None:
        with pytest.raises(CredentialCacheError, match="cannot be read"):
            default_ccache_path()
    else:
        assert default_ccache_path() == result


# --- AS / TGS state machines against an in-test KDC -------------------------------

REALM = "EXAMPLE.TEST"
SALT = "EXAMPLE.TESTalice"
NOW = 1_800_000_000.0


class _Kdc:
    """Just enough KDC to exercise the client: preauth, AS-REP, TGS-REP."""

    def __init__(self, password="secret", *, bad_nonce=False):
        self.user_key = string_to_key(18, password, SALT)
        self.tgs_key = Key(18, b"\x11" * 32)
        self.svc_key = Key(18, b"\x22" * 32)
        self.session = Key(18, b"\x33" * 32)
        self.svc_session = Key(18, b"\x44" * 32)
        self.bad_nonce = bad_nonce
        self.seen_ts = None

    def _err(self, code, e_data=None):
        e = {
            "pvno": 5,
            "msg_type": 30,
            "stime": dt.datetime.fromtimestamp(NOW, dt.UTC),
            "susec": 0,
            "error_code": code,
            "realm": REALM,
            "sname": {"name_type": 2, "name_string": ["krbtgt", REALM]},
        }
        if e_data is not None:
            e["e_data"] = e_data
        return m.KrbError(e).dump()

    def _ticket(self, key, sname, session):
        enc = crypto.encrypt(key, 2, b"opaque-" + session.contents)
        return m.Ticket(
            {
                "tkt_vno": 5,
                "realm": REALM,
                "sname": sname,
                "enc_part": {"etype": 18, "kvno": 1, "cipher": enc},
            }
        )

    def _part(self, cls, session, nonce, sname):
        t = dt.datetime.fromtimestamp(NOW, dt.UTC)
        return cls(
            {
                "key": {"keytype": 18, "keyvalue": session.contents},
                "last_req": [],
                "nonce": nonce,
                "flags": b"\x40\xe1\x00\x00",
                "authtime": t,
                "endtime": t + dt.timedelta(hours=10),
                "srealm": REALM,
                "sname": sname,
            }
        ).dump()

    def as_req(self, raw):
        req = m.ASReq.load(raw)
        pas = {p["padata_type"].native: p["padata_value"].native for p in req["padata"]}
        if m.PA_ENC_TIMESTAMP not in pas:
            info = m.ETypeInfo2([{"etype": 18, "salt": SALT}]).dump()
            return self._err(25, m.MethodData([{"padata_type": 19, "padata_value": info}]).dump())
        enc = m.EncryptedData.load(pas[m.PA_ENC_TIMESTAMP])
        try:
            ts = m.PAEncTsEnc.load(crypto.decrypt(self.user_key, 1, enc["cipher"].native))
        except crypto.IntegrityError:
            return self._err(24)  # KDC_ERR_PREAUTH_FAILED
        self.seen_ts = ts["patimestamp"].native
        body = req["req_body"]
        sname = {"name_type": 2, "name_string": ["krbtgt", REALM]}
        nonce = body["nonce"].native + (1 if self.bad_nonce else 0)
        part = self._part(m.EncASRepPart, self.session, nonce, sname)
        return m.ASRep(
            {
                "pvno": 5,
                "msg_type": 11,
                "crealm": REALM,
                "cname": {"name_type": 1, "name_string": ["alice"]},
                "ticket": self._ticket(self.tgs_key, sname, self.session),
                "enc_part": {"etype": 18, "cipher": crypto.encrypt(self.user_key, 3, part)},
            }
        ).dump()

    def tgs_req(self, raw):
        req = m.TGSReq.load(raw)
        (pa,) = req["padata"]
        ap = m.APReq.load(pa["padata_value"].native)
        auth = m.Authenticator.load(
            crypto.decrypt(self.session, 7, ap["authenticator"]["cipher"].native)
        )
        body = req["req_body"]
        ck = auth["cksum"]
        # A field value's dump() keeps the field's [4] tag; the checksum covers the
        # bare KDC-REQ-BODY.
        bare = parser.parse(body.dump())[4]
        crypto.verify_checksum(self.session, 6, bare, ck["cksumtype"].native, ck["checksum"].native)
        sname = body["sname"].native
        part = self._part(m.EncTGSRepPart, self.svc_session, body["nonce"].native, sname)
        return m.TGSRep(
            {
                "pvno": 5,
                "msg_type": 13,
                "crealm": REALM,
                "cname": {"name_type": 1, "name_string": ["alice"]},
                "ticket": self._ticket(self.svc_key, sname, self.svc_session),
                "enc_part": {"etype": 18, "cipher": crypto.encrypt(self.session, 8, part)},
            }
        ).dump()


def _tgt(kdc, password="secret"):
    ex = AsExchange(Principal.parse("alice@" + REALM), password=password, clock=lambda: NOW)
    out = ex.process(kdc.as_req(ex.request()))
    assert isinstance(out, bytes)  # preauth round
    return ex.process(kdc.as_req(out))


def test_as_exchange_with_preauth_and_salt_from_kdc():
    kdc = _Kdc()
    tgt = _tgt(kdc)
    assert isinstance(tgt, Credential)
    assert tgt.session_key == kdc.session
    assert str(tgt.server) == f"krbtgt/{REALM}@{REALM}"
    assert kdc.seen_ts == dt.datetime.fromtimestamp(NOW, dt.UTC)
    assert m.Ticket.load(tgt.ticket)["realm"].native == REALM  # bare DER, no field tag


def test_as_exchange_wrong_password_reports_kdc_error():
    with pytest.raises(KerberosError) as ei:
        _tgt(_Kdc(), password="wrong")
    assert ei.value.code == 24
    assert "wrong" not in str(ei.value)


def test_as_exchange_nonce_mismatch_rejected():
    with pytest.raises(KerberosError, match="nonce"):
        _tgt(_Kdc(bad_nonce=True))


def test_as_exchange_with_keytab_key():
    kdc = _Kdc()
    ex = AsExchange(Principal.parse("alice@" + REALM), keys=[kdc.user_key], clock=lambda: NOW)
    out = ex.process(kdc.as_req(ex.request()))
    assert ex.process(kdc.as_req(out)).session_key == kdc.session


def test_tgs_exchange():
    kdc = _Kdc()
    tgt = _tgt(kdc)
    tgs = TgsExchange(tgt, Principal.parse("svc@" + REALM), clock=lambda: NOW)
    st = tgs.process(kdc.tgs_req(tgs.request()))
    assert st.session_key == kdc.svc_session
    assert str(st.server) == f"svc@{REALM}"


def test_credential_repr_hides_secrets():
    tgt = _tgt(_Kdc())
    assert (b"\x33" * 32).hex() not in repr(tgt)
    assert "redacted" in repr(tgt)


# --- live (integration) ----------------------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_KRB5_KDC"), reason="SAPRFC_KRB5_KDC not set — no live KDC"
)
def test_live_as_and_tgs():
    kdc = (os.environ["SAPRFC_KRB5_KDC"], 88)
    ex = AsExchange(
        Principal.parse(os.environ["SAPRFC_KRB5_USER"]), password=os.environ["SAPRFC_KRB5_PASSWORD"]
    )
    out = ex.process(kdc_roundtrip(kdc, ex.request()))
    if isinstance(out, bytes):
        out = ex.process(kdc_roundtrip(kdc, out))
    assert isinstance(out, Credential)
    tgs = TgsExchange(out, Principal.parse(os.environ["SAPRFC_KRB5_SERVICE"]))
    st = tgs.process(kdc_roundtrip(kdc, tgs.request()))
    assert st.session_key.enctype in (17, 18)
