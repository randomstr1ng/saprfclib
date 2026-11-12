# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Built-in SNC mechanism, replayed against recorded sessions.

Two golden fixtures drive these tests (see their JSON for provenance):

* ``secgss_live_handshake`` — a live handshake against a SAP system;
* ``secgss_loopback_records`` — a handshake plus wrap/MIC records exchanged with
  SAP CommonCryptoLib acting as the acceptor.

The replay feeds the initiator the recorded clock, random bytes and ephemeral key,
so every client token must come out byte-identical, and every recorded peer token
must be accepted. No private key is stored: the recorded client signature is
injected and verified against the client certificate over the regenerated
transcript.
"""

import json
import pathlib
import struct

import pytest
from asn1crypto import x509
from hypothesis import given, settings
from hypothesis import strategies as st
from tlslite.utils.python_rsakey import Python_RSAKey

from saprfclib import secgss
from saprfclib.exceptions import SncError
from saprfclib.secgss import (
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    SecGssInitiator,
    SncCredential,
    _p_sha256,
    own_name_matches,
    parse_snc_name,
)

GOLDEN = pathlib.Path(__file__).parent / "golden" / "snc"


# The client's AuthRequest list when these sessions were recorded: RSA only. Since then
# the client also offers the ECDSA ids, which changes its AuthRequest and with it every
# transcript-dependent byte, so the replays run the client with the list it had at
# recording time. _offer_as_recorded checks that list against the recorded token.
_RECORDED_OFFER = (0x01000601, 0x01000201)


def _load(name):
    return json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _offer_as_recorded(monkeypatch):
    listed = b"".join(struct.pack(">I", a) for a in _RECORDED_OFFER)
    element = b"\x04" + bytes([len(listed) + 3]) + struct.pack(">I", len(listed))[1:] + listed
    for name in ("secgss_live_handshake", "secgss_loopback_records"):
        fx = _load(name)
        client_token_2 = bytes.fromhex([t for t in fx["tokens"] if t["dir"] == "C>S"][1]["hex"])
        assert element in client_token_2, f"{name}: recorded AuthRequest list differs"
    monkeypatch.setattr(secgss, "_OFFERED_SIGALGS", _RECORDED_OFFER)


class _Replay:
    """Recorded inputs for one session, injected into a SecGssInitiator."""

    def __init__(self, fx):
        self.fx = fx
        self._random = [bytes.fromhex(r) for r in fx["random"]]
        self._sigs = [bytes.fromhex(s["sig"]) for s in fx["signatures"]]
        self.cert = x509.Certificate.load(bytes.fromhex(fx["certificate_chain"][0]))

    def random(self, n):
        b = self._random.pop(0)
        assert len(b) == n, "replay diverged: random request of a different size"
        return b

    def signer(self, data, hash_name):
        sig = self._sigs.pop(0)
        pub = self.cert.public_key["public_key"].parsed
        key = Python_RSAKey(pub["modulus"].native, pub["public_exponent"].native)
        # The recorded signature must verify over the transcript we regenerated:
        # proves the transcript is byte-identical to the one signed live.
        assert key.hashAndVerify(bytearray(sig), bytearray(data), "PKCS1", hash_name)
        return sig

    def initiator(self, *, partner=None, trusted=None, clock=None):
        fx = self.fx
        cred = SncCredential(
            private_key=b"",
            certificate_chain=tuple(bytes.fromhex(c) for c in fx["certificate_chain"]),
            trusted=tuple(
                bytes.fromhex(c) for c in (fx["trusted"] if trusted is None else trusted)
            ),
        )
        return SecGssInitiator(
            cred,
            partner or fx["partner_name"],
            random=self.random,
            clock=clock or (lambda: fx["clock"]),
            ecdh_private_key=bytes.fromhex(fx["ecdh_private_key"]),
            signer=self.signer,
        )


def _handshake(fx, g):
    toks = [(t["dir"], bytes.fromhex(t["hex"])) for t in fx["tokens"]]
    majors = []
    inp = b""
    i = 0
    while True:
        maj, out = g.init_sec_context(inp)
        majors.append(maj)
        if out:
            assert toks[i][0] == "C>S"
            assert out == toks[i][1], f"client token {i} differs from the recording"
            i += 1
        if maj == GSS_S_COMPLETE:
            break
        assert toks[i][0] == "S>C"
        inp = toks[i][1]
        i += 1
    assert i == len(toks)
    return majors


@pytest.mark.parametrize("name", ["secgss_live_handshake", "secgss_loopback_records"])
def test_handshake_replays_byte_for_byte(name):
    fx = _load(name)
    g = _Replay(fx).initiator()
    assert _handshake(fx, g) == [GSS_S_CONTINUE_NEEDED, GSS_S_CONTINUE_NEEDED, GSS_S_COMPLETE]
    assert g.established
    assert g.peer_certificate == bytes.fromhex(fx["trusted"][0])


def test_loopback_records_replay():
    fx = _load("secgss_loopback_records")
    r = _Replay(fx)
    g = r.initiator()
    _handshake(fx, g)
    for rec in fx["records"]:
        plain = bytes.fromhex(rec["plain_hex"])
        if rec["kind"] == "wrap":
            assert g.wrap(plain) == bytes.fromhex(rec["token"])
            assert g.unwrap(bytes.fromhex(rec["reply"])) == b"echo:" + plain
        else:
            assert g.get_mic(plain) == bytes.fromhex(rec["token"])
            g.verify_mic(b"mic:" + plain, bytes.fromhex(rec["reply"]))
    assert not r._random, "recorded random bytes left unused"


def _established_loopback():
    fx = _load("secgss_loopback_records")
    g = _Replay(fx).initiator()
    _handshake(fx, g)
    return fx, g


def test_replayed_record_is_rejected_as_duplicate():
    fx, g = _established_loopback()
    rec = fx["records"][0]
    g.wrap(bytes.fromhex(rec["plain_hex"]))
    reply = bytes.fromhex(rec["reply"])
    g.unwrap(reply)
    with pytest.raises(SncError) as ei:
        g.unwrap(reply)
    assert ei.value.major == 0x2


def test_skipped_record_is_rejected_as_gap():
    fx, g = _established_loopback()
    with pytest.raises(SncError) as ei:
        g.unwrap(bytes.fromhex(fx["records"][2]["reply"]))  # sequence 2, expecting 1
    assert ei.value.major == 0x10


def test_tampered_record_is_rejected():
    fx, g = _established_loopback()
    reply = bytearray(bytes.fromhex(fx["records"][0]["reply"]))
    reply[-1] ^= 1
    with pytest.raises(SncError):
        g.unwrap(bytes(reply))


def test_empty_wrap_is_refused():
    _, g = _established_loopback()
    with pytest.raises(ValueError):
        g.wrap(b"")


def test_data_calls_before_handshake_are_refused():
    g = _Replay(_load("secgss_live_handshake")).initiator()
    for call in (lambda: g.wrap(b"x"), lambda: g.unwrap(b"x"), lambda: g.get_mic(b"x")):
        with pytest.raises(SncError):
            call()


def _final_step_error(**kw):
    fx = _load("secgss_live_handshake")
    g = _Replay(fx).initiator(**kw)
    toks = [bytes.fromhex(t["hex"]) for t in fx["tokens"]]
    g.init_sec_context(b"")
    g.init_sec_context(toks[1])
    with pytest.raises(SncError) as ei:
        g.init_sec_context(toks[3])
    return ei.value


def test_wrong_partner_name_fails_closed():
    err = _final_step_error(partner="p:CN=A4H")
    assert "name" in str(err)


def test_untrusted_server_fails_closed():
    other = _load("secgss_loopback_records")["trusted"]
    err = _final_step_error(trusted=other)
    assert "trusted" in str(err)


def test_expired_server_certificate_fails_closed():
    # First call stamps the ClientHello (must match the recording); the later
    # call checks certificate validity: year 2039, past the server's notAfter.
    times = [_load("secgss_live_handshake")["clock"]]
    err = _final_step_error(clock=lambda: times.pop(0) if times else 2_200_000_000)
    assert "expired" in str(err)


def test_tampered_server_token_fails():
    fx = _load("secgss_live_handshake")
    g = _Replay(fx).initiator()
    toks = [bytes.fromhex(t["hex"]) for t in fx["tokens"]]
    g.init_sec_context(b"")
    g.init_sec_context(toks[1])
    bad = bytearray(toks[3])
    bad[200] ^= 0x01  # inside the server signature / certificate
    with pytest.raises(SncError):
        g.init_sec_context(bytes(bad))
    with pytest.raises(SncError):  # a failed context cannot be resumed
        g.init_sec_context(toks[3])


def test_server_choosing_another_suite_is_refused():
    fx = _load("secgss_live_handshake")
    g = _Replay(fx).initiator()
    toks = [bytes.fromhex(t["hex"]) for t in fx["tokens"]]
    g.init_sec_context(b"")
    s1 = toks[1]
    i = s1.index(bytes.fromhex("0408010100090000"))  # ServerHello params: 1.1, suite 9
    tampered = s1[: i + 4] + b"\x00\x0a" + s1[i + 6 :]
    with pytest.raises(SncError, match="cipher suite"):
        g.init_sec_context(tampered)


@pytest.mark.parametrize(
    "token",
    [b"", b"\x30\x00", b"\x30\x82\x00\x08\x06\x06\x2b\x24\x03\x01\x25\x01", b"\x00" * 64],
)
def test_malformed_server_token_is_rejected(token):
    g = _Replay(_load("secgss_live_handshake")).initiator()
    g.init_sec_context(b"")
    with pytest.raises(SncError):
        g.init_sec_context(token)


@settings(max_examples=50, deadline=None)
@given(st.binary(max_size=600))
def test_fuzzed_server_token_never_crashes(token):
    g = _Replay(_load("secgss_live_handshake")).initiator()
    g.init_sec_context(b"")
    with pytest.raises(SncError):
        g.init_sec_context(token)


def test_p_sha256_rfc5246_vector():
    # Widely published TLS 1.2 PRF (SHA-256) test vector.
    secret = bytes.fromhex("9bbe436ba940f017b17652849a71db35")
    seed = bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c")
    out = _p_sha256(secret, b"test label" + seed, 100)
    assert out.hex().startswith("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a")


@pytest.mark.parametrize(
    "name",
    [
        "p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE",
        "p:cn=a4h,ou=idemosystem,ou=sap web as,o=sap trust community,c=de",
        "p:CN=A4H; OU=IDEMOSYSTEM; OU=SAP Web AS; O=SAP Trust Community; C=DE",
        '"p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP Web AS, O=SAP Trust Community, C=DE"',
    ],
)
def test_partner_name_accepted_forms(name):
    cert = bytes.fromhex(_load("secgss_live_handshake")["trusted"][0])
    assert own_name_matches(SncCredential(b"", (cert,)), name)


@pytest.mark.parametrize(
    "name",
    [
        "p:CN=A4H",
        "p:C=DE, O=SAP Trust Community, OU=SAP Web AS, OU=IDEMOSYSTEM, CN=A4H",
        "p:CN=A4H, OU=SAP Web AS, OU=IDEMOSYSTEM, O=SAP Trust Community, C=DE",
        "p:CN=A4H, OU=IDEMOSYSTEM, OU=SAP  Web AS, O=SAP Trust Community, C=DE",
    ],
)
def test_partner_name_rejected_forms(name):
    cert = bytes.fromhex(_load("secgss_live_handshake")["trusted"][0])
    assert not own_name_matches(SncCredential(b"", (cert,)), name)


@pytest.mark.parametrize("name", ["CN=A4H", "p:", "p:CN=", "p:XX=1", 'p:CN="a,b"', "p:CN=a+O=b"])
def test_unsupported_names_raise(name):
    with pytest.raises(ValueError):
        parse_snc_name(name)


def test_wrap_token_layout():
    _, g = _established_loopback()
    tok = g.wrap(b"x" * 17)
    assert tok[:2] == b"\x30\x84"
    assert struct.unpack(">I", tok[2:6])[0] == len(tok) - 6
    assert tok[6:14] == b"\x06\x06\x2b\x24\x03\x01\x25\x01"
    assert tok[14:16] == b"\x04\x0a"
    assert tok[24:26] == b"\x01\x01"
    assert tok[26:28] == b"\x04\x84"
    # 16-byte IV + 17 data + 32 MAC + 15 pad = 80 bytes of body.
    assert struct.unpack(">I", tok[28:32])[0] == len(tok) - 32 == 80


def test_no_secret_in_error_messages():
    fx = _load("secgss_live_handshake")
    err = _final_step_error(partner="p:CN=SECRETNAME")
    assert "SECRETNAME" not in str(err)
    assert fx["ecdh_private_key"] not in repr(err)


def test_sn_in_a_partner_name_is_serial_number() -> None:
    # As the SNC extension header encodes it (snc._RDN_OID): SN is serialNumber, not
    # surname, so the partner name and the certificate are compared the same way.
    from saprfclib.secgss import parse_snc_name

    assert dict(parse_snc_name("p:CN=x, SN=123"))["2.5.4.5"] == "123"
