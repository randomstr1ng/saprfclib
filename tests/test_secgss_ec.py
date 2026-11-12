# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Built-in SNC mechanism with ECDSA keys, replayed against CommonCryptoLib.

Golden fixtures (see their JSON for provenance):

* ``secgss_ec_loopback`` — client and server keys ECDSA P-256, plus the tokens of
  CommonCryptoLib itself as the client against the same server (``reference_tokens``);
* ``secgss_ec_client_rsa_server`` — client key ECDSA P-384, server key RSA.

As in ``test_secgss.py``, the recorded clock, random bytes and ephemeral key are fed
back, every client token must come out byte-identical, and the recorded client
signature is injected and verified over the regenerated transcript.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest
from asn1crypto import core, keys, x509
from ecdsa import NIST256p, SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der

from saprfclib import secgss
from saprfclib.exceptions import SncError
from saprfclib.pse import load_pse
from saprfclib.secgss import GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, SecGssInitiator, SncCredential

GOLDEN = pathlib.Path(__file__).parent / "golden"
FIXTURES = ["secgss_ec_loopback", "secgss_ec_client_rsa_server"]


def _load(name: str) -> dict:
    return json.loads((GOLDEN / "snc" / f"{name}.json").read_text(encoding="utf-8"))


class _Replay:
    def __init__(self, fx: dict) -> None:
        self.fx = fx
        self._random = [bytes.fromhex(r) for r in fx["random"]]
        self._sigs = [bytes.fromhex(s["sig"]) for s in fx["signatures"]]
        self.cert = x509.Certificate.load(bytes.fromhex(fx["certificate_chain"][0]))

    def random(self, n: int) -> bytes:
        b = self._random.pop(0)
        assert len(b) == n, "replay diverged: random request of a different size"
        return b

    def signer(self, data: bytes, hash_name: str) -> bytes:
        sig = self._sigs.pop(0)
        vk = VerifyingKey.from_der(self.cert.public_key.dump())
        # Proves the regenerated transcript is byte-identical to the one signed.
        assert vk.verify(sig, data, hashfunc=getattr(hashlib, hash_name), sigdecode=sigdecode_der)
        return sig

    def initiator(self) -> SecGssInitiator:
        fx = self.fx
        cred = SncCredential(
            private_key=b"",
            certificate_chain=tuple(bytes.fromhex(c) for c in fx["certificate_chain"]),
            trusted=tuple(bytes.fromhex(c) for c in fx["trusted"]),
        )
        return SecGssInitiator(
            cred,
            fx["partner_name"],
            random=self.random,
            clock=lambda: fx["clock"],
            ecdh_private_key=bytes.fromhex(fx["ecdh_private_key"]),
            signer=self.signer,
        )


def _handshake(fx: dict, g: SecGssInitiator) -> list[int]:
    toks = [(t["dir"], bytes.fromhex(t["hex"])) for t in fx["tokens"]]
    majors, inp, i = [], b"", 0
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


@pytest.mark.parametrize("name", FIXTURES)
def test_handshake_and_records_replay(name: str) -> None:
    fx = _load(name)
    r = _Replay(fx)
    g = r.initiator()
    assert _handshake(fx, g) == [GSS_S_CONTINUE_NEEDED, GSS_S_CONTINUE_NEEDED, GSS_S_COMPLETE]
    assert g.established
    for rec in fx["records"]:
        plain = bytes.fromhex(rec["plain_hex"])
        if rec["kind"] == "wrap":
            assert g.wrap(plain) == bytes.fromhex(rec["token"])
            assert g.unwrap(bytes.fromhex(rec["reply"])) == b"echo:" + plain
        else:
            assert g.get_mic(plain) == bytes.fromhex(rec["token"])
            g.verify_mic(b"mic:" + plain, bytes.fromhex(rec["reply"]))
    assert not r._random and not r._sigs


def test_server_key_type_is_what_the_fixtures_claim() -> None:
    assert _peer_key_algorithm("secgss_ec_loopback") == "ec"
    assert _peer_key_algorithm("secgss_ec_client_rsa_server") == "rsa"


def _peer_key_algorithm(name: str) -> str:
    fx = _load(name)
    g = _Replay(fx).initiator()
    _handshake(fx, g)
    assert g.peer_certificate is not None
    return str(x509.Certificate.load(g.peer_certificate).public_key.algorithm)


def test_tampered_server_signature_is_rejected() -> None:
    fx = _load("secgss_ec_loopback")
    final = bytearray.fromhex(fx["tokens"][3]["hex"])
    # The server AuthResponse signature ends just before the certificate list; flip a
    # byte inside the DER signature value.
    marker = bytes.fromhex(secgss._SIGALG_ALGID[secgss._SIGALG_ECDSA_SHA512].hex())
    at = bytes(final).index(marker) + len(marker) + 12
    final[at] ^= 0x01
    fx["tokens"][3]["hex"] = final.hex()
    with pytest.raises(SncError):
        _handshake(fx, _Replay(fx).initiator())


# --- what the reference client sends ------------------------------------------------


def _reference_auth_response() -> tuple[bytes, bytes]:
    """AlgorithmIdentifier DER and BIT STRING contents of the reference AuthResponse."""
    tok = bytes.fromhex(_load("secgss_ec_loopback")["reference_tokens"][2]["hex"])
    algid = secgss._SIGALG_ALGID[secgss._SIGALG_ECDSA_SHA512]
    at = tok.index(algid)
    bits = core.BitString.load(tok[at + len(algid) :])
    return algid, bits.contents


def test_reference_client_signs_with_ecdsa_sha512_oid_only() -> None:
    algid, bits = _reference_auth_response()
    alg = x509.AlgorithmIdentifier.load(algid)
    assert alg["algorithm"].dotted == "1.2.840.10045.4.3.4"
    assert alg["parameters"].native is None and len(algid) == 12  # no NULL parameters
    assert bits[0] == 0  # no unused bits, then a DER Ecdsa-Sig-Value
    sig = core.Sequence.load(bits[1:])
    assert [type(sig[i]).__name__ for i in range(2)] == ["Integer", "Integer"]


def test_reference_client_lists_rsa_before_ecdsa() -> None:
    tok = bytes.fromhex(_load("secgss_ec_loopback")["reference_tokens"][2]["hex"])
    ids = secgss._OFFERED_SIGALGS
    listed = [tok.find(i.to_bytes(4, "big")) for i in ids]
    assert all(p > 0 for p in listed)
    assert listed == sorted(listed), "built-in order differs from the reference list"


# --- own key and signature choice ---------------------------------------------------


def _pse_credential(name: str) -> SncCredential:
    meta = json.loads((GOLDEN / "pse" / f"{name}.json").read_text(encoding="utf-8"))
    return load_pse((GOLDEN / "pse" / f"{name}.pse").read_bytes(), meta["pin"])


@pytest.mark.parametrize("name,curve", [("pse_ec_p256_nopin", NIST256p), ("pse_ec_p384_pin", None)])
def test_own_ec_signer_signs_verifiably(name: str, curve: object) -> None:
    cred = _pse_credential(name)
    cert = x509.Certificate.load(cred.certificate)
    kind, sign = secgss._own_signer(cred, cert)
    assert kind == "ec"
    sig = sign(b"transcript", "sha512")
    vk = VerifyingKey.from_der(cert.public_key.dump())
    assert vk.verify(sig, b"transcript", hashfunc=hashlib.sha512, sigdecode=sigdecode_der)


def test_own_key_must_match_own_certificate() -> None:
    cred = _pse_credential("pse_ec_p256_nopin")
    other = SigningKey.generate(curve=NIST256p).to_der(format="pkcs8")
    bad = SncCredential(private_key=other, certificate_chain=cred.certificate_chain)
    with pytest.raises(SncError, match="does not match"):
        SecGssInitiator(bad, "p:CN=x")


def test_unsupported_curve_is_refused() -> None:
    cred = _pse_credential("pse_ec_p256_nopin")
    k1 = SigningKey.generate(curve=SECP256k1).to_der(format="pkcs8")
    assert keys.PrivateKeyInfo.load(k1).curve[1] == "secp256k1"
    bad = SncCredential(private_key=k1, certificate_chain=cred.certificate_chain)
    with pytest.raises(SncError, match="unsupported curve"):
        SecGssInitiator(bad, "p:CN=x")


def test_signature_must_match_certificate_key_type() -> None:
    cert = x509.Certificate.load(_pse_credential("pse_ec_p256_nopin").certificate)
    with pytest.raises(SncError, match="does not match the certificate key"):
        secgss._verify_signature(cert, secgss._SIGALG_RSA_PKCS1_SHA512, b"sig", b"data")


def test_ec_key_needs_an_ecdsa_id_from_the_server() -> None:
    fx = _load("secgss_ec_loopback")
    server_first = bytearray.fromhex(fx["tokens"][1]["hex"])
    for ecdsa_id in (0x00000606, 0x00000506, 0x00000206):
        i = bytes(server_first).index(ecdsa_id.to_bytes(4, "big"))
        server_first[i : i + 4] = (0x01000201).to_bytes(4, "big")  # an RSA id instead
    fx["tokens"][1]["hex"] = server_first.hex()
    g = _Replay(fx).initiator()
    g.init_sec_context(b"")
    with pytest.raises(SncError, match="no common signature algorithm"):
        g.init_sec_context(bytes(server_first))
