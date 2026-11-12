# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Pure-Python initiator for the X.509 SNC mechanism spoken by SAP CommonCryptoLib.

This is the GSS mechanism identified by OID ``1.3.36.3.1.37.1``. It replaces the
native GSS library for the client role: :class:`SecGssInitiator` exposes the same
``init_sec_context`` / ``wrap`` / ``unwrap`` / ``get_mic`` / ``verify_mic`` surface
that :class:`saprfclib.snc.SncTransport` drives on a ctypes
:class:`~saprfclib.snc.GssBinding`, so the SNC frame layer is unchanged.

Sans-I/O: no sockets, no clocks or randomness taken implicitly — both are
injectable, which is what lets the golden fixtures replay a recorded live session
byte for byte.

Scope, and why it is this narrow (see ``docs/protocol/snc-mechanism.md``): every
value below was observed on the wire against a live SAP system and re-derived from
the captured bytes. The only parameter set implemented is the one observed end to
end:

* protocol version 1.1, cipher suite ``0x0009`` — ephemeral ECDH on P-256 chosen by
  the server, AES-256-CBC, HMAC-SHA256, the TLS 1.2 ``P_SHA256`` PRF;
* X.509 authentication of both sides with RSA PKCS#1 v1.5 or ECDSA signatures
  (P-256, P-384, P-521 keys).

Anything else the peer selects is refused with :class:`~saprfclib.exceptions.SncError`
rather than attempted.

Crypto primitives come from maintained third-party pure-Python libraries — AES from
``tlslite-ng``, RSA from ``tlslite-ng``, ECDH and ECDSA from ``ecdsa``, certificate and key
parsing from ``asn1crypto`` — plus ``hashlib``/``hmac`` from the standard library.
None of these primitives are constant-time; see the security notes in the docs.

Security: no key, secret, token, certificate or name ever enters a log record, a
``repr`` or an exception message. Errors carry a fixed description only.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from asn1crypto import keys as _keys
from asn1crypto import x509 as _x509
from ecdsa import ECDH, NIST256p, NIST384p, NIST521p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der
from tlslite.utils.cipherfactory import createAES
from tlslite.utils.python_rsakey import Python_RSAKey

from saprfclib.exceptions import SncError
from saprfclib.krb5.client import Credential
from saprfclib.krb5.crypto import ENCTYPE_AES128, ENCTYPE_AES256
from saprfclib.krb5.crypto import encrypt as krb5_encrypt

__all__ = [
    "GSS_S_COMPLETE",
    "GSS_S_CONTINUE_NEEDED",
    "SncCredential",
    "SecGssInitiator",
    "SecGssKerberosInitiator",
    "own_name_matches",
    "parse_snc_name",
]

GSS_S_COMPLETE = 0
GSS_S_CONTINUE_NEEDED = 1

# GSS major status values (RFC 2744 routine errors) used for failures.
_GSS_S_DEFECTIVE_TOKEN = 0x00090000
_GSS_S_FAILURE = 0x000D0000
_GSS_S_DUPLICATE_TOKEN = 0x00000002
_GSS_S_GAP_TOKEN = 0x00000010

# Mechanism OID 1.3.36.3.1.37.1 as a DER TLV. Source: every handshake and data
# token in the 2026-11-08 live captures starts SEQUENCE{this OID, ...}.
_MECH_OID_TLV = b"\x06\x06\x2b\x24\x03\x01\x25\x01"

# --- negotiated parameter set (all observed on the wire, 2026-11-08) -------
# ClientHello parameter list ids, ServerHello v1.1 parameters. Source: golden
# fixture secgss_live_handshake (ClientHello params, ServerHello params
# 01 01 0009 00004000).
_VERSION_1_1 = (1, 1)
_MAC_HMAC_SHA256 = 1
_CIPHER_AES256 = 1
_HS_HASH_SHA256 = 2
_PRF_PHASH_SHA256 = 2
_ENCODING_DATA_HEADER_V1 = 2
_KEX_SERVER_ECDHE = 4
_SUITE_ECDHE_P256_AES256_SHA256 = 0x0009
# Kerberos key exchange: key-exchange list id 1, suite 0x0007 (AES-256-CBC,
# HMAC-SHA256, P_SHA256: the suite 9 record layer with a Kerberos key exchange).
# Source: live handshake against an SAP system, 2026-11-10 — a ClientHello offering
# key exchange 01 / suite 00 07 was answered with ServerHello 01 01 0007 00004000.
_KEX_KERBEROS = 1
_SUITE_KERBEROS_AES256_SHA256 = 0x0007
# Key usage for the encrypted pre-master secret. Source: the same live handshake —
# the server accepted a pre-master secret encrypted with usage 2 and answered with
# a valid Finished.
_KRB5_USAGE_PMS = 2

# Hello extension ids. 3 = client cipher-suite list (BE u16 ids), 5 = NULL flag
# sent by the reference client. Source: golden fixture ClientHello extensions.
_EXT_CLIENT_CIPHER_SUITES = 3
_EXT_CLIENT_IS_NOT_SLC = 5

# Signature algorithm ids carried in AuthRequest (BE u32). Source: golden fixture
# AuthRequest lists; the server answered with sha512WithRSAEncryption when 0x01000601
# was listed first.
_SIGALG_RSA_PKCS1_SHA512 = 0x01000601
_SIGALG_RSA_PKCS1_SHA256 = 0x01000201
# ECDSA ids. Source: behavioural probe 2026-11-12 — a CommonCryptoLib acceptor with an
# EC key, offered exactly one id, signed with ecdsa-with-SHA512 for 00000606, -SHA384
# for 00000506 and -SHA256 for 00000206, and aborted for every other id it lists;
# golden fixture snc/secgss_ec_loopback.json.
_SIGALG_ECDSA_SHA512 = 0x00000606
_SIGALG_ECDSA_SHA384 = 0x00000506
_SIGALG_ECDSA_SHA256 = 0x00000206
_SIGALG_HASH: dict[int, str] = {
    _SIGALG_RSA_PKCS1_SHA512: "sha512",
    _SIGALG_RSA_PKCS1_SHA256: "sha256",
    _SIGALG_ECDSA_SHA512: "sha512",
    _SIGALG_ECDSA_SHA384: "sha384",
    _SIGALG_ECDSA_SHA256: "sha256",
}
# The key type each id signs with.
_SIGALG_KEY: dict[int, str] = {
    _SIGALG_RSA_PKCS1_SHA512: "rsa",
    _SIGALG_RSA_PKCS1_SHA256: "rsa",
    _SIGALG_ECDSA_SHA512: "ec",
    _SIGALG_ECDSA_SHA384: "ec",
    _SIGALG_ECDSA_SHA256: "ec",
}
# X.509 AlgorithmIdentifier for each, DER as observed: OID + NULL parameters for RSA,
# the OID alone for ECDSA (fixture secgss_ec_loopback.json, both sides).
_SIGALG_ALGID: dict[int, bytes] = {
    _SIGALG_RSA_PKCS1_SHA512: bytes.fromhex("300d06092a864886f70d01010d0500"),
    _SIGALG_RSA_PKCS1_SHA256: bytes.fromhex("300d06092a864886f70d01010b0500"),
    _SIGALG_ECDSA_SHA512: bytes.fromhex("300a06082a8648ce3d040304"),
    _SIGALG_ECDSA_SHA384: bytes.fromhex("300a06082a8648ce3d040303"),
    _SIGALG_ECDSA_SHA256: bytes.fromhex("300a06082a8648ce3d040302"),
}
_ALGID_OID_TO_SIGALG: dict[str, int] = {
    "1.2.840.113549.1.1.13": _SIGALG_RSA_PKCS1_SHA512,
    "1.2.840.113549.1.1.11": _SIGALG_RSA_PKCS1_SHA256,
    "1.2.840.10045.4.3.4": _SIGALG_ECDSA_SHA512,
    "1.2.840.10045.4.3.3": _SIGALG_ECDSA_SHA384,
    "1.2.840.10045.4.3.2": _SIGALG_ECDSA_SHA256,
}
# What we offer the server for *its* signature, most preferred first. RSA before
# ECDSA, strongest hash first within each, as in the reference client's list
# (fixture secgss_ec_loopback.json: ... 01000601 01000201 ... 00000606 00000506 00000206).
_OFFERED_SIGALGS = (
    _SIGALG_RSA_PKCS1_SHA512,
    _SIGALG_RSA_PKCS1_SHA256,
    _SIGALG_ECDSA_SHA512,
    _SIGALG_ECDSA_SHA384,
    _SIGALG_ECDSA_SHA256,
)
# EC curves accepted for own keys and peer certificates: the ones sapgenpse creates and
# the handshake was verified with (golden fixtures pse_ec_*, secgss_ec_loopback.json).
_EC_CURVES = {"secp256r1": NIST256p, "secp384r1": NIST384p, "secp521r1": NIST521p}

# Handshake message tags (context-specific, constructed unless noted).
_TAG_CONTAINER = 0xA0
_TAG_CLIENT_HELLO = 0xA1
_TAG_SERVER_HELLO = 0xA2
_TAG_KEY_EXCHANGE_KEY = 0xA3
_TAG_AUTH_REQUEST = 0xA4
_TAG_AUTH_RESPONSE = 0xA5
_TAG_KEY_TRANSPORT = 0xA6
_TAG_FINISHED = 0x87  # primitive: OCTET STRING holding one data token
_TAG_ALERT = 0xAA

# Sizes for suite 0x0009.
_AES_BLOCK = 16
_MAC_LEN = 32
_KEY_BLOCK_LEN = 32 + 32 + 16  # mac key || enc key || iv
_MASTER_LEN = 48
_FINISHED_LEN = 12
_MAX_TOKEN_BYTES = 128 * 1024 * 1024  # same DoS cap as the SNC frame layer

# Data-token header: 32 bytes. kind/conf byte pair is 01 01 for wrap, 00 00 for MIC.
_WRAP_FLAGS = b"\x01\x01"
_MIC_FLAGS = b"\x00\x00"


# ---------------------------------------------------------------------------
# Minimal DER helpers (definite lengths only)
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _tlv_long2(tag: int, content: bytes) -> bytes:
    """TLV whose length is always written in the two-byte long form (``82 HH LL``).

    The reference implementation writes the outer token SEQUENCE and the message
    container this way regardless of size (golden fixture secgss_live_handshake).
    """
    if len(content) > 0xFFFF:
        raise SncError("handshake token too large")
    return bytes([tag, 0x82]) + struct.pack(">H", len(content)) + content


def _der_int(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return _tlv(0x02, b)


@dataclass(frozen=True)
class _Tlv:
    tag: int
    value: bytes
    raw: bytes  # the complete TLV as received (tag + length + value)


def _read_tlv(buf: bytes, pos: int = 0) -> tuple[_Tlv, int]:
    if pos + 2 > len(buf):
        raise SncError("truncated handshake element", major=_GSS_S_DEFECTIVE_TOKEN)
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise SncError("unsupported multi-byte tag", major=_GSS_S_DEFECTIVE_TOKEN)
    n = buf[pos + 1]
    i = pos + 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(buf):
            raise SncError("bad element length", major=_GSS_S_DEFECTIVE_TOKEN)
        n = int.from_bytes(buf[i : i + k], "big")
        i += k
    end = i + n
    if end > len(buf):
        raise SncError("truncated handshake element", major=_GSS_S_DEFECTIVE_TOKEN)
    return _Tlv(tag, buf[i:end], buf[pos:end]), end


def _read_all(buf: bytes) -> list[_Tlv]:
    out: list[_Tlv] = []
    pos = 0
    while pos < len(buf):
        t, pos = _read_tlv(buf, pos)
        out.append(t)
    return out


def _expect(t: _Tlv, tag: int, what: str) -> _Tlv:
    if t.tag != tag:
        raise SncError(f"unexpected element in {what}", major=_GSS_S_DEFECTIVE_TOKEN)
    return t


# ---------------------------------------------------------------------------
# PRF (TLS 1.2 P_hash) and record keys
# ---------------------------------------------------------------------------


def _p_sha256(secret: bytes, seed: bytes, n: int) -> bytes:
    """``P_SHA256(secret, seed)`` truncated to ``n`` bytes (RFC 5246 §5).

    Label and seed parts are concatenated into ``seed`` by the caller. Source:
    golden fixture secgss_loopback_records — the Finished values and every record
    replay byte for byte only with the keys this function derives from the recorded
    inputs.
    """
    out = bytearray()
    a = seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return bytes(out[:n])


class _Direction:
    """One direction of the record layer: keys, sequence number, running MAC.

    The MAC is *cumulative*: one HMAC-SHA256 object per direction is fed every MAC
    input since the keys were derived, and each record carries the digest of all
    of it so far (wrap and MIC records share the state). It is never reset. Source:
    golden fixture secgss_loopback_records — every record of both directions, server
    records included, verifies only under this rule.
    """

    def __init__(self, mac_key: bytes, enc_key: bytes) -> None:
        self._enc_key = enc_key
        self._mac = hmac.new(mac_key, digestmod=hashlib.sha256)
        self.seq = 0

    def mac(self, data: bytes) -> bytes:
        self._mac.update(data)
        return self._mac.copy().digest()

    def encrypt(self, iv: bytes, data: bytes) -> bytes:
        return bytes(createAES(bytearray(self._enc_key), bytearray(iv)).encrypt(bytearray(data)))

    def decrypt(self, iv: bytes, data: bytes) -> bytes:
        return bytes(createAES(bytearray(self._enc_key), bytearray(iv)).decrypt(bytearray(data)))


def _record_header(seq: int, length: int, index: int) -> bytes:
    # BE64 seq || BE32 length || BE32 chunk index || version major || version minor.
    # Source: golden fixture secgss_loopback_records (recomputed MAC inputs).
    return struct.pack(">QII", seq, length, index) + bytes(_VERSION_1_1)


def _token_header(seq: int, flags: bytes, body_len: int) -> bytes:
    inner = _MECH_OID_TLV + b"\x04\x0a" + struct.pack(">Q", seq) + flags
    inner += b"\x04\x84" + struct.pack(">I", body_len)
    return b"\x30\x84" + struct.pack(">I", len(inner) + body_len) + inner


def _parse_token(token: bytes, flags: bytes) -> tuple[int, bytes]:
    """Split a v1.1 data token into (sequence number, body); validate the framing."""
    if len(token) > _MAX_TOKEN_BYTES:
        raise SncError("data token exceeds size limit", major=_GSS_S_DEFECTIVE_TOKEN)
    outer, end = _read_tlv(token)
    if outer.tag != 0x30 or end != len(token):
        raise SncError("bad data token framing", major=_GSS_S_DEFECTIVE_TOKEN)
    v = outer.value
    if not v.startswith(_MECH_OID_TLV):
        raise SncError("data token for a different mechanism", major=_GSS_S_DEFECTIVE_TOKEN)
    hdr, pos = _read_tlv(v, len(_MECH_OID_TLV))
    if hdr.tag != 0x04 or len(hdr.value) != 10:
        raise SncError("bad data token header", major=_GSS_S_DEFECTIVE_TOKEN)
    if hdr.value[8:10] != flags:
        raise SncError("data token of the wrong kind", major=_GSS_S_DEFECTIVE_TOKEN)
    body, pos = _read_tlv(v, pos)
    if body.tag != 0x04 or pos != len(v):
        raise SncError("bad data token body", major=_GSS_S_DEFECTIVE_TOKEN)
    return int.from_bytes(hdr.value[:8], "big"), body.value


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

# X.500 attribute abbreviations → OIDs (X.520 / RFC 4519 assignments), with one SAP
# difference: in an SNC name SN means serialNumber (2.5.4.5), not surname. That is how the
# reference library encodes SN in the names it exports (probe partner names, 2026-11-08,
# see snc._RDN_OID), so a partner name is matched against the certificate the same way.
_ATTR_OIDS: dict[str, str] = {
    "CN": "2.5.4.3",
    "SN": "2.5.4.5",
    "SERIALNUMBER": "2.5.4.5",
    "C": "2.5.4.6",
    "L": "2.5.4.7",
    "ST": "2.5.4.8",
    "SP": "2.5.4.8",
    "STREET": "2.5.4.9",
    "O": "2.5.4.10",
    "OU": "2.5.4.11",
    "T": "2.5.4.12",
    "TITLE": "2.5.4.12",
    "G": "2.5.4.42",
    "GIVENNAME": "2.5.4.42",
    "E": "1.2.840.113549.1.9.1",
    "EMAIL": "1.2.840.113549.1.9.1",
    "DC": "0.9.2342.19200300.100.1.25",
    "UID": "0.9.2342.19200300.100.1.1",
}


def parse_snc_name(name: str) -> tuple[tuple[str, str], ...]:
    """Parse an SNC ``p:`` name into ``(attribute OID, value)`` pairs, most specific first.

    Accepts ``,`` or ``;`` as RDN separators and ignores whitespace around them, as a
    live server does. Quoting or escaping inside values is not supported and is
    refused rather than interpreted.
    """
    text = name.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    if not text.lower().startswith("p:"):
        raise ValueError("SNC name must use the 'p:' (X.509 distinguished name) form")
    text = text[2:]
    if '"' in text or "\\" in text or "+" in text:
        raise ValueError("quoted, escaped or multi-valued RDNs in SNC names are not supported")
    out: list[tuple[str, str]] = []
    for part in text.replace(";", ",").split(","):
        attr, sep, value = part.partition("=")
        attr = attr.strip().upper()
        value = value.strip()
        if not sep or not attr or not value:
            raise ValueError("malformed RDN in SNC name")
        oid = _ATTR_OIDS.get(attr)
        if oid is None:
            raise ValueError("unsupported attribute type in SNC name")
        out.append((oid, value))
    if not out:
        raise ValueError("empty SNC name")
    return tuple(out)


def _cert_subject_rdns(cert: _x509.Certificate) -> tuple[tuple[str, str], ...]:
    """Certificate subject as (OID, value) pairs, most specific (last DER RDN) first."""
    rdns: list[tuple[str, str]] = []
    for rdn in cert.subject.chosen:
        if len(rdn) != 1:
            raise SncError("multi-valued RDN in peer certificate subject")
        atv = rdn[0]
        value = atv["value"].native
        if not isinstance(value, str):
            raise SncError("unsupported attribute value in peer certificate subject")
        rdns.append((atv["type"].dotted, value))
    rdns.reverse()
    return tuple(rdns)


def _names_match(expected: Sequence[tuple[str, str]], actual: Sequence[tuple[str, str]]) -> bool:
    """RDN-by-RDN, in order, attribute and value compared case-insensitively.

    Inner whitespace of a value is significant. Source: live behavioural probe
    2026-11-08 (docs/protocol/snc.md, partner-name table).
    """
    if len(expected) != len(actual):
        return False
    return all(
        eo == ao and ev.casefold() == av.casefold()
        for (eo, ev), (ao, av) in zip(expected, actual, strict=True)
    )


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class SncCredential:
    """Own private key + certificate chain + trusted certificates.

    ``private_key`` is a PKCS#8 ``PrivateKeyInfo`` or PKCS#1 ``RSAPrivateKey`` DER.
    ``certificate_chain`` starts with the own certificate. ``trusted`` holds the
    certificates accepted as trust anchors for the server (a PSE's PK list).

    ``repr`` is suppressed: a credential never appears in logs or tracebacks.
    """

    private_key: bytes
    certificate_chain: tuple[bytes, ...]
    trusted: tuple[bytes, ...] = field(default=())

    def __repr__(self) -> str:
        return "SncCredential(<redacted>)"

    @property
    def certificate(self) -> bytes:
        return self.certificate_chain[0]


def _ec_curve(curve: tuple[str, Any]) -> Any:
    kind, name = curve
    if kind != "named" or name not in _EC_CURVES:
        raise SncError("EC key uses an unsupported curve; P-256, P-384 and P-521 are")
    return _EC_CURVES[name]


def _own_signer(credential: SncCredential, cert: _x509.Certificate) -> tuple[str, Signer]:
    """The key type of the own certificate and a signer for its private key.

    The signer gets the data and a hash name and returns the signature value: RSA
    PKCS#1 v1.5, or for EC a DER ``Ecdsa-Sig-Value`` (RFC 3279), the form the
    reference client sends (fixture secgss_ec_loopback.json).
    """
    kind = cert.public_key.algorithm
    if kind == "rsa":
        rsa = _rsa_private(credential.private_key)

        def sign_rsa(data: bytes, hash_name: str) -> bytes:
            return bytes(rsa.hashAndSign(bytearray(data), "PKCS1", hash_name))

        return kind, sign_rsa
    if kind != "ec":
        raise SncError("own certificate key is neither RSA nor EC")
    try:
        info = _keys.PrivateKeyInfo.load(credential.private_key)
        if info.algorithm != "ec":
            raise SncError("own private key does not match the own certificate")
        curve = _ec_curve(info.curve)
        secret = info["private_key"].parsed["private_key"].native
    except ValueError as e:
        raise SncError("own EC private key is malformed") from e
    sk = SigningKey.from_secret_exponent(secret, curve=curve)
    if sk.get_verifying_key().to_string() != _ec_public(cert).to_string():
        raise SncError("own private key does not match the own certificate")

    def sign_ec(data: bytes, hash_name: str) -> bytes:
        # RFC 6979 deterministic nonce: no dependence on the random source.
        return bytes(
            sk.sign_deterministic(
                data, hashfunc=getattr(hashlib, hash_name), sigencode=sigencode_der
            )
        )

    return kind, sign_ec


def _ec_public(cert: _x509.Certificate) -> VerifyingKey:
    pki = cert.public_key
    _ec_curve(pki.curve)
    try:
        return VerifyingKey.from_der(pki.dump())
    except Exception as e:  # ecdsa raises several types for a bad point or encoding
        raise SncError("certificate EC public key is malformed") from e


def _verify_signature(cert: _x509.Certificate, sigalg: int, signature: bytes, data: bytes) -> bool:
    """Verify a handshake signature made with ``sigalg`` by the key of ``cert``."""
    kind = _SIGALG_KEY[sigalg]
    if cert.public_key.algorithm != kind:
        raise SncError("signature algorithm does not match the certificate key")
    if kind == "rsa":
        return _verify_rsa(_rsa_public(cert), sigalg, signature, data)
    vk = _ec_public(cert)  # outside the try: an unsupported curve is its own error
    try:
        return bool(
            vk.verify(
                signature,
                data,
                hashfunc=getattr(hashlib, _SIGALG_HASH[sigalg]),
                sigdecode=sigdecode_der,
            )
        )
    except Exception:  # BadSignatureError, or malformed DER/point: not a valid signature
        return False


def _rsa_private(der: bytes) -> Python_RSAKey:
    try:
        info = _keys.PrivateKeyInfo.load(der)
        if info.algorithm != "rsa":
            raise SncError("own key is not an RSA key")
        rsa = info["private_key"].parsed
    except ValueError:
        rsa = _keys.RSAPrivateKey.load(der)
    n = rsa["modulus"].native
    return Python_RSAKey(
        n,
        rsa["public_exponent"].native,
        rsa["private_exponent"].native,
        rsa["prime1"].native,
        rsa["prime2"].native,
        rsa["exponent1"].native,
        rsa["exponent2"].native,
        rsa["coefficient"].native,
    )


def _rsa_public(cert: _x509.Certificate) -> Python_RSAKey:
    pki = cert.public_key
    if pki.algorithm != "rsa":
        raise SncError("certificate key is not RSA, but the signature to verify is an RSA one")
    pub = pki["public_key"].parsed
    return Python_RSAKey(pub["modulus"].native, pub["public_exponent"].native)


def _verify_rsa(key: Python_RSAKey, sigalg: int, signature: bytes, data: bytes) -> bool:
    return bool(
        key.hashAndVerify(bytearray(signature), bytearray(data), "PKCS1", _SIGALG_HASH[sigalg])
    )


# ---------------------------------------------------------------------------
# Certificate trust
# ---------------------------------------------------------------------------

_CERT_SIG_HASHES = frozenset({"sha256", "sha384", "sha512"})


def _cert_signed_by(child: _x509.Certificate, issuer: _x509.Certificate) -> bool:
    """True if ``issuer`` names ``child``'s issuer and signs it (RSA PKCS#1 v1.5 or ECDSA)."""
    if child.issuer != issuer.subject:
        return False
    algo = child["signature_algorithm"]
    try:
        scheme = algo.signature_algo
        h = algo.hash_algo
    except ValueError:
        return False
    if h not in _CERT_SIG_HASHES:
        return False
    tbs = child["tbs_certificate"].dump()
    sig = child["signature_value"].native
    if scheme == "rsassa_pkcs1v15":
        try:
            key = _rsa_public(issuer)
        except SncError:
            return False
        return bool(key.hashAndVerify(bytearray(sig), bytearray(tbs), "PKCS1", h))
    if scheme == "ecdsa":
        try:
            vk = _ec_public(issuer) if issuer.public_key.algorithm == "ec" else None
            if vk is None:
                return False
            return bool(vk.verify(sig, tbs, hashfunc=getattr(hashlib, h), sigdecode=sigdecode_der))
        except Exception:  # bad signature, malformed DER or point: not signed by issuer
            return False
    return False


def _check_validity(cert: _x509.Certificate, now: float) -> None:
    validity = cert["tbs_certificate"]["validity"]
    not_before = validity["not_before"].native.timestamp()
    not_after = validity["not_after"].native.timestamp()
    if not (not_before <= now <= not_after):
        raise SncError("peer certificate is expired or not yet valid")


def _check_key_usage(cert: _x509.Certificate) -> None:
    ku = cert.key_usage_value
    if ku is not None and "digital_signature" not in ku.native:
        raise SncError("peer certificate key usage does not allow signing")


def _verify_chain(
    chain: Sequence[bytes], trusted: Sequence[bytes], now: float
) -> _x509.Certificate:
    """Return the peer's leaf certificate if it is trusted, else raise.

    Trusted means: the leaf itself is one of ``trusted``, or a chain of RSA or
    ECDSA signatures over certificates the peer sent leads to one of ``trusted``. Expiry
    is checked on every certificate on the path; key usage on the leaf.
    """
    if not chain:
        raise SncError("peer sent no certificate")
    if not trusted:
        raise SncError("no trusted certificates configured for the SNC partner")
    leaf = _x509.Certificate.load(chain[0])
    anchors = [_x509.Certificate.load(t) for t in trusted]
    intermediates = [_x509.Certificate.load(c) for c in chain[1:]]
    _check_key_usage(leaf)
    _check_validity(leaf, now)
    if any(a.dump() == leaf.dump() for a in anchors):
        return leaf
    current = leaf
    for _depth in range(8):
        for anchor in anchors:
            if _cert_signed_by(current, anchor):
                _check_validity(anchor, now)
                return leaf
        nxt = next((c for c in intermediates if _cert_signed_by(current, c)), None)
        if nxt is None:
            break
        _check_validity(nxt, now)
        current = nxt
    raise SncError("peer certificate is not trusted")


# ---------------------------------------------------------------------------
# The initiator
# ---------------------------------------------------------------------------

RandomSource = Callable[[int], bytes]
Signer = Callable[[bytes, str], bytes]
Clock = Callable[[], float]


class _SecGssContext:
    """Record layer, key schedule and token framing shared by both key exchanges.

    A subclass runs the handshake: it sets ``_client_random``, ``_server_random``
    and ``_chunk_size`` and calls :meth:`_derive_keys`.
    """

    # Attributes SncTransport reads on a binding.
    _real = False
    _lib: Any = None
    # Suites this context accepts in the ServerHello.
    _accepted_suites: frozenset[int] = frozenset()

    def _init_state(self, random: RandomSource, clock: Clock) -> None:
        self._random = random
        self._clock = clock
        self._step = 0
        self._transcript = bytearray()
        self._client_random = b""
        self._server_random = b""
        self._master = b""
        self._send: _Direction | None = None
        self._recv: _Direction | None = None
        self._chunk_size = 0
        self.established = False

    def _discard_handshake_state(self) -> None:
        self._master = b""
        self._transcript = bytearray()

    def _client_hello(self, kex: int, suite: int) -> bytes:
        # random = BE32 seconds since the epoch || 28 random bytes.
        self._client_random = struct.pack(">I", int(self._clock()) & 0xFFFFFFFF) + self._random(28)
        params = (
            bytes([2]) + bytes(_VERSION_1_1)
            + bytes([1, _MAC_HMAC_SHA256])
            + bytes([1, _CIPHER_AES256])
            + bytes([1, _HS_HASH_SHA256])
            + bytes([1, _PRF_PHASH_SHA256])
            + bytes([1, _ENCODING_DATA_HEADER_V1])
            + bytes([1, kex])
        )  # fmt: skip
        ext_suites = _tlv(
            0x30, _der_int(_EXT_CLIENT_CIPHER_SUITES) + _tlv(0x04, struct.pack(">H", suite))
        )
        ext_not_slc = _tlv(0x30, _der_int(_EXT_CLIENT_IS_NOT_SLC) + b"\x05\x00")
        return _tlv(
            _TAG_CLIENT_HELLO,
            _tlv(0x04, params)
            + _tlv(0x04, self._client_random)
            + _tlv(0xA1, ext_suites + ext_not_slc),
        )

    def wrap(self, payload: bytes) -> bytes:
        self._require_established()
        if not payload:
            # The reference implementation fails an empty wrap and consumes the
            # sequence number; never produce one.
            raise ValueError("cannot wrap an empty payload")
        assert self._send is not None
        return self._wrap(self._send, payload)

    def unwrap(self, token: bytes) -> bytes:
        self._require_established()
        assert self._recv is not None
        return self._unwrap(self._recv, token)

    def get_mic(self, payload: bytes) -> bytes:
        self._require_established()
        assert self._send is not None
        d = self._send
        body = bytearray()
        for i, chunk in enumerate(self._chunks(payload)):
            body += d.mac(_record_header(d.seq, len(chunk), i) + chunk)
        token = _token_header(d.seq, _MIC_FLAGS, len(body)) + bytes(body)
        d.seq += 1
        return token

    def verify_mic(self, payload: bytes, mic: bytes) -> None:
        self._require_established()
        assert self._recv is not None
        d = self._recv
        seq, body = _parse_token(mic, _MIC_FLAGS)
        self._check_seq(d, seq)
        chunks = self._chunks(payload)
        if len(body) != _MAC_LEN * len(chunks):
            raise SncError("bad MIC length", major=_GSS_S_DEFECTIVE_TOKEN)
        ok = True
        for i, chunk in enumerate(chunks):
            expect = d.mac(_record_header(seq, len(chunk), i) + chunk)
            ok &= hmac.compare_digest(expect, body[i * _MAC_LEN : (i + 1) * _MAC_LEN])
        if not ok:
            raise SncError("MIC verification failed", major=_GSS_S_DEFECTIVE_TOKEN)
        d.seq += 1

    def close(self) -> None:
        self._discard_handshake_state()
        self._send = None
        self._recv = None
        self.established = False

    def _chunks(self, payload: bytes) -> list[bytes]:
        size = self._chunk_size
        return [payload[i : i + size] for i in range(0, len(payload), size)] or [b""]

    def _wrap(self, d: _Direction, payload: bytes) -> bytes:
        body = bytearray()
        for i, chunk in enumerate(self._chunks(payload)):
            # Pad value is the pad length itself, 1..16 bytes; padding is inside the
            # MAC (MAC-then-encrypt). Source: golden fixture secgss_loopback_records.
            padlen = _AES_BLOCK - ((len(chunk) + _MAC_LEN) % _AES_BLOCK)
            pad = bytes([padlen]) * padlen
            mac = d.mac(_record_header(d.seq, len(chunk) + padlen, i) + chunk + pad)
            iv = self._random(_AES_BLOCK)
            body += iv + d.encrypt(iv, chunk + pad + mac)
        token = _token_header(d.seq, _WRAP_FLAGS, len(body)) + bytes(body)
        d.seq += 1
        return token

    @staticmethod
    def _check_seq(d: _Direction, seq: int) -> None:
        if seq < d.seq:
            raise SncError("replayed SNC token", major=_GSS_S_DUPLICATE_TOKEN)
        if seq > d.seq:
            raise SncError("SNC token out of sequence", major=_GSS_S_GAP_TOKEN)

    def _unwrap(self, d: _Direction, token: bytes) -> bytes:
        seq, body = _parse_token(token, _WRAP_FLAGS)
        self._check_seq(d, seq)
        unit = ((_AES_BLOCK + _MAC_LEN + self._chunk_size) | (_AES_BLOCK - 1)) + 1
        out = bytearray()
        pos = 0
        index = 0
        while pos < len(body) or index == 0:
            seg = body[pos : pos + unit]
            pos += len(seg)
            ct = seg[_AES_BLOCK:]
            if len(ct) % _AES_BLOCK or len(ct) < _MAC_LEN + _AES_BLOCK:
                raise SncError("bad record length", major=_GSS_S_DEFECTIVE_TOKEN)
            plain = d.decrypt(seg[:_AES_BLOCK], ct)
            inner, mac = plain[:-_MAC_LEN], plain[-_MAC_LEN:]
            expect = d.mac(_record_header(seq, len(inner), index) + inner)
            if not hmac.compare_digest(expect, mac):
                raise SncError("record MAC verification failed", major=_GSS_S_DEFECTIVE_TOKEN)
            padlen = inner[-1]
            if not 1 <= padlen <= _AES_BLOCK or inner[-padlen:] != bytes([padlen]) * padlen:
                raise SncError("bad record padding", major=_GSS_S_DEFECTIVE_TOKEN)
            out += inner[:-padlen]
            index += 1
        d.seq += 1
        return bytes(out)

    def _require_established(self) -> None:
        if not self.established:
            raise SncError("SNC security context is not established")

    def _emit(self, messages: Sequence[bytes]) -> bytes:
        for m in messages:
            self._transcript += m
        container = _tlv_long2(_TAG_CONTAINER, b"".join(messages))
        return _tlv_long2(0x30, _MECH_OID_TLV + container)

    def _open(self, token: bytes) -> list[_Tlv]:
        if len(token) > _MAX_TOKEN_BYTES:
            raise SncError("handshake token exceeds size limit", major=_GSS_S_DEFECTIVE_TOKEN)
        outer, end = _read_tlv(token)
        if outer.tag != 0x30 or end != len(token) or not outer.value.startswith(_MECH_OID_TLV):
            raise SncError("bad handshake token header", major=_GSS_S_DEFECTIVE_TOKEN)
        container, end = _read_tlv(outer.value, len(_MECH_OID_TLV))
        if container.tag != _TAG_CONTAINER or end != len(outer.value):
            raise SncError("unsupported handshake token body", major=_GSS_S_DEFECTIVE_TOKEN)
        msgs = _read_all(container.value)
        if any(m.tag == _TAG_ALERT for m in msgs):
            raise SncError("SNC partner aborted the handshake", major=_GSS_S_FAILURE)
        return msgs

    def _finished_token(self, label: str) -> bytes:
        verify = _p_sha256(
            self._master,
            label.encode("ascii") + hashlib.sha256(self._transcript).digest(),
            _FINISHED_LEN,
        )
        assert self._send is not None
        self._send.seq = 0  # Finished is record 0; data records start at 1
        return self._wrap(self._send, verify)

    def _derive_keys(self, pms: bytes) -> None:
        cr, sr = self._client_random, self._server_random
        self._master = _p_sha256(pms, b"master secret" + cr + sr, _MASTER_LEN)
        cw = _p_sha256(self._master, b"client write key expansion" + sr + cr, _KEY_BLOCK_LEN)
        sw = _p_sha256(self._master, b"server write key expansion" + sr + cr, _KEY_BLOCK_LEN)
        # Each block: mac key[32] || enc key[32] || iv[16]; the iv is unused because
        # every record carries its own.
        self._send = _Direction(cw[:32], cw[32:64])
        self._recv = _Direction(sw[:32], sw[32:64])

    def _parse_server_hello(self, m: _Tlv) -> None:
        fields = _read_all(m.value)
        if len(fields) < 2:
            raise SncError("malformed ServerHello", major=_GSS_S_DEFECTIVE_TOKEN)
        params = _expect(fields[0], 0x04, "ServerHello").value
        rnd = _expect(fields[1], 0x04, "ServerHello").value
        if len(rnd) != 32:
            raise SncError("malformed ServerHello random", major=_GSS_S_DEFECTIVE_TOKEN)
        if len(params) != 8 or tuple(params[:2]) != _VERSION_1_1:
            raise SncError("server selected an unsupported SNC protocol version")
        suite, chunk = struct.unpack(">HI", params[2:8])
        if suite not in self._accepted_suites:
            raise SncError("server selected an unsupported SNC cipher suite")
        if chunk == 0 or chunk > _MAX_TOKEN_BYTES:
            raise SncError("server announced an invalid chunk size")
        self._server_random = rnd
        self._chunk_size = chunk


class SecGssInitiator(_SecGssContext):
    """Client side of the mechanism; drop-in for :class:`saprfclib.snc.GssBinding`.

    ``init_sec_context`` is called with the peer's last token (``b""`` first) and
    returns ``(major, output_token)`` exactly like ``gss_init_sec_context``:
    ``CONTINUE_NEEDED`` twice, then ``COMPLETE`` with an empty output token.

    ``random`` and ``clock`` exist for deterministic replay in tests; production
    callers leave them at their defaults (``os.urandom``, ``time.time``).
    ``ecdh_private_key`` likewise pins the ephemeral scalar for replay only, and
    ``signer`` replaces signing with the credential's private key (it receives the
    data to sign and the hash name, and returns an RSA PKCS#1 v1.5 signature, or a
    DER ``Ecdsa-Sig-Value`` when the own certificate has an EC key).
    """

    _accepted_suites = frozenset({_SUITE_ECDHE_P256_AES256_SHA256})

    def __init__(
        self,
        credential: SncCredential,
        partner_name: str,
        *,
        random: RandomSource = os.urandom,
        clock: Clock = time.time,
        ecdh_private_key: bytes | None = None,
        signer: Signer | None = None,
    ) -> None:
        self._cred = credential
        self._partner = parse_snc_name(partner_name)
        self._ecdh_fixed = ecdh_private_key
        self._own_cert = _x509.Certificate.load(credential.certificate)
        if signer is None:
            self._key_kind, signer = _own_signer(credential, self._own_cert)
        else:
            self._key_kind = self._own_cert.public_key.algorithm
            if self._key_kind not in ("rsa", "ec"):
                raise SncError("own certificate key is neither RSA nor EC")
        self._sign: Signer = signer
        self._init_state(random, clock)
        self._server_sigalgs: list[int] = []
        self._ecdh: ECDH | None = None
        self.peer_certificate: bytes | None = None

    def init_sec_context(self, input_token: bytes) -> tuple[int, bytes]:
        try:
            if self._step == 0:
                if input_token:
                    raise SncError("unexpected input token on first call")
                self._step = 1
                return GSS_S_CONTINUE_NEEDED, self._token1()
            if self._step == 1:
                out = self._process_server_first(input_token)
                self._step = 2
                return GSS_S_CONTINUE_NEEDED, out
            if self._step == 2:
                self._process_server_final(input_token)
                self._step = 3
                self.established = True
                self._discard_handshake_state()
                return GSS_S_COMPLETE, b""
            raise SncError("security context already established")
        except SncError:
            self._step = 99  # a failed handshake cannot be resumed
            self._discard_handshake_state()
            raise

    def _token1(self) -> bytes:
        return self._emit([self._client_hello(_KEX_SERVER_ECDHE, _SUITE_ECDHE_P256_AES256_SHA256)])

    def _process_server_first(self, token: bytes) -> bytes:
        msgs = self._open(token)
        if [m.tag for m in msgs] != [_TAG_SERVER_HELLO, _TAG_KEY_EXCHANGE_KEY, _TAG_AUTH_REQUEST]:
            raise SncError("unexpected handshake message sequence", major=_GSS_S_DEFECTIVE_TOKEN)
        sh, kek, areq = msgs
        self._parse_server_hello(sh)
        peer_point = self._parse_key_exchange(kek)
        self._parse_server_auth_request(areq)
        for m in msgs:
            self._transcript += m.raw

        # Key exchange: ephemeral P-256 ECDH; premaster = X coordinate, 32 bytes.
        ecdh = ECDH(curve=NIST256p)
        if self._ecdh_fixed is not None:
            ecdh.load_private_key_bytes(self._ecdh_fixed)
        else:
            ecdh.generate_private_key()
        try:
            ecdh.load_received_public_key_bytes(peer_point, valid_encodings=["uncompressed"])
            pms = bytes(ecdh.generate_sharedsecret_bytes())
        except Exception as exc:  # ecdsa raises several types for a bad point
            raise SncError("invalid ECDH public key from server", major=_GSS_S_FAILURE) from exc
        self._ecdh = ecdh
        own_point = ecdh.get_public_key().to_string("uncompressed")
        self._derive_keys(pms)

        key_transport = _tlv(_TAG_KEY_TRANSPORT, _tlv(0x83, own_point))
        sigalgs = b"".join(struct.pack(">I", a) for a in _OFFERED_SIGALGS)
        auth_request = _tlv(
            _TAG_AUTH_REQUEST,
            _tlv(0xA1, _tlv(0x04, struct.pack(">I", len(sigalgs))[1:] + sigalgs)),
        )
        self._transcript += key_transport + auth_request

        # The first id in the server's list that the own key can sign with (the
        # reference client picks the same way; fixture secgss_ec_loopback.json).
        sigalg = next(
            (a for a in self._server_sigalgs if _SIGALG_KEY.get(a) == self._key_kind), None
        )
        if sigalg is None:
            raise SncError("no common signature algorithm with the server", major=_GSS_S_FAILURE)
        signature = self._sign(bytes(self._transcript), _SIGALG_HASH[sigalg])
        sig = _tlv(0x30, _SIGALG_ALGID[sigalg] + _tlv(0x03, b"\x00" + signature))
        certs = _tlv(0x30, b"".join(self._cred.certificate_chain))
        auth_response = _tlv(_TAG_AUTH_RESPONSE, _tlv(0xA1, sig + certs))
        self._transcript += auth_response

        finished = _tlv(_TAG_FINISHED, self._finished_token("client finished"))
        self._transcript += finished
        container = _tlv_long2(
            _TAG_CONTAINER, key_transport + auth_request + auth_response + finished
        )
        return _tlv_long2(0x30, _MECH_OID_TLV + container)

    def _process_server_final(self, token: bytes) -> None:
        msgs = self._open(token)
        if [m.tag for m in msgs] != [_TAG_AUTH_RESPONSE, _TAG_FINISHED]:
            raise SncError("unexpected handshake message sequence", major=_GSS_S_DEFECTIVE_TOKEN)
        aresp, fin = msgs
        sigalg, signature, chain = self._parse_auth_response(aresp)
        leaf = _verify_chain(chain, self._cred.trusted, self._clock())
        if not _verify_signature(leaf, sigalg, signature, bytes(self._transcript)):
            raise SncError("server handshake signature is invalid", major=_GSS_S_FAILURE)
        if not _names_match(self._partner, _cert_subject_rdns(leaf)):
            raise SncError("SNC partner name does not match the server certificate")
        self.peer_certificate = leaf.dump()
        self._transcript += aresp.raw

        # Server Finished: verify_data over the transcript up to its AuthResponse.
        expect = _p_sha256(
            self._master,
            b"server finished" + hashlib.sha256(self._transcript).digest(),
            _FINISHED_LEN,
        )
        assert self._recv is not None
        self._recv.seq = 0
        got = self._unwrap(self._recv, fin.value)
        if not hmac.compare_digest(got, expect):
            raise SncError("server Finished verification failed", major=_GSS_S_FAILURE)

    def _parse_key_exchange(self, m: _Tlv) -> bytes:
        inner, end = _read_tlv(m.value)
        if inner.tag != 0xA2 or end != len(m.value):
            raise SncError("expected an ECDH key exchange from the server")
        try:
            spki = _keys.PublicKeyInfo.load(b"\x30" + inner.raw[1:])
            if spki.algorithm != "ec" or spki.curve != ("named", "secp256r1"):
                raise SncError("server ECDH key is not on P-256")
            point = bytes(spki["public_key"])
        except ValueError as exc:
            raise SncError("malformed server ECDH key", major=_GSS_S_DEFECTIVE_TOKEN) from exc
        return point

    def _parse_server_auth_request(self, m: _Tlv) -> None:
        reqs = _read_all(m.value)
        x509 = next((r for r in reqs if r.tag == 0xA1), None)
        if x509 is None:
            raise SncError("server does not request X.509 authentication")
        fields = _read_all(x509.value)
        sigalg_field = next((f for f in fields if f.tag == 0x04), None)
        if sigalg_field is None:
            raise SncError("malformed AuthRequest", major=_GSS_S_DEFECTIVE_TOKEN)
        raw = sigalg_field.value
        if len(raw) < 3 or int.from_bytes(raw[:3], "big") != len(raw) - 3 or (len(raw) - 3) % 4:
            raise SncError("malformed AuthRequest signature list", major=_GSS_S_DEFECTIVE_TOKEN)
        self._server_sigalgs = [
            int.from_bytes(raw[i : i + 4], "big") for i in range(3, len(raw), 4)
        ]

    def _parse_auth_response(self, m: _Tlv) -> tuple[int, bytes, list[bytes]]:
        inner, end = _read_tlv(m.value)
        if inner.tag != 0xA1 or end != len(m.value):
            raise SncError("expected an X.509 AuthResponse from the server")
        fields = _read_all(inner.value)
        if not fields:
            raise SncError("malformed AuthResponse", major=_GSS_S_DEFECTIVE_TOKEN)
        sig_fields = _read_all(_expect(fields[0], 0x30, "AuthResponse").value)
        if len(sig_fields) != 2:
            raise SncError("malformed AuthResponse signature", major=_GSS_S_DEFECTIVE_TOKEN)
        _expect(sig_fields[0], 0x30, "AuthResponse")
        oid = _x509.AlgorithmIdentifier.load(sig_fields[0].raw)["algorithm"].dotted
        sigalg = _ALGID_OID_TO_SIGALG.get(oid)
        if sigalg is None or sigalg not in _OFFERED_SIGALGS:
            raise SncError("server used a signature algorithm that was not offered")
        bits = _expect(sig_fields[1], 0x03, "AuthResponse").value
        if not bits or bits[0] != 0:
            raise SncError("malformed AuthResponse signature", major=_GSS_S_DEFECTIVE_TOKEN)
        chain: list[bytes] = []
        if len(fields) > 1:
            chain = [c.raw for c in _read_all(_expect(fields[1], 0x30, "AuthResponse").value)]
        return sigalg, bits[1:], chain

    def _discard_handshake_state(self) -> None:
        super()._discard_handshake_state()
        self._ecdh = None


class SecGssKerberosInitiator(_SecGssContext):
    """Client side of the mechanism with a Kerberos key exchange (suite ``0x0007``).

    ``service_ticket`` is a ticket for the server's Kerberos principal — the name in
    the ``CN`` of its SNC name ``p:CN=<service>@<REALM>`` — with an AES session key.
    The client proves it holds that session key by encrypting the pre-master secret
    with it; the server proves it could decrypt the ticket by producing a valid
    Finished. There is no authenticator and no AP-REQ (see
    ``docs/protocol/snc-mechanism.md``).

    ``init_sec_context`` returns ``CONTINUE_NEEDED`` with the first token, then
    ``COMPLETE`` *with* a final output token (the client Finished), which the SNC
    layer sends and the server acknowledges with an ACCEPT_ACK frame.

    ``random`` and ``clock`` are injectable for deterministic replay only.
    """

    _accepted_suites = frozenset({_SUITE_KERBEROS_AES256_SHA256})

    def __init__(
        self,
        service_ticket: Credential,
        *,
        random: RandomSource = os.urandom,
        clock: Clock = time.time,
    ) -> None:
        if service_ticket.session_key.enctype not in (ENCTYPE_AES128, ENCTYPE_AES256):
            raise SncError("Kerberos session key type is not supported")
        self._ticket = service_ticket
        self._pms = b""
        self._init_state(random, clock)

    def init_sec_context(self, input_token: bytes) -> tuple[int, bytes]:
        try:
            if self._step == 0:
                if input_token:
                    raise SncError("unexpected input token on first call")
                self._step = 1
                return GSS_S_CONTINUE_NEEDED, self._token1()
            if self._step == 1:
                out = self._process_server(input_token)
                self._step = 2
                self.established = True
                self._discard_handshake_state()
                return GSS_S_COMPLETE, out
            raise SncError("security context already established")
        except SncError:
            self._step = 99  # a failed handshake cannot be resumed
            self._discard_handshake_state()
            raise

    def _discard_handshake_state(self) -> None:
        super()._discard_handshake_state()
        self._pms = b""

    def _token1(self) -> bytes:
        hello = self._client_hello(_KEX_KERBEROS, _SUITE_KERBEROS_AES256_SHA256)
        # KeyExchangeKey, Kerberos alternative: A3 { A0 { OCTET STRING Ticket } }.
        kek = _tlv(_TAG_KEY_EXCHANGE_KEY, _tlv(0xA0, _tlv(0x04, self._ticket.ticket)))
        # Pre-master secret: 48 bytes, the first two the protocol version offered
        # (1.1), the rest random. Encrypted with the ticket's session key, RFC 3961
        # encryption with key usage 2, and sent as KeyTransport alternative [1].
        self._pms = bytes(_VERSION_1_1) + self._random(46)
        ct = krb5_encrypt(self._ticket.session_key, _KRB5_USAGE_PMS, self._pms, random=self._random)
        key_transport = _tlv(_TAG_KEY_TRANSPORT, _tlv(0x81, ct))
        return self._emit([hello, kek, key_transport])

    def _process_server(self, token: bytes) -> bytes:
        msgs = self._open(token)
        if [m.tag for m in msgs] != [_TAG_SERVER_HELLO, _TAG_FINISHED]:
            raise SncError("unexpected handshake message sequence", major=_GSS_S_DEFECTIVE_TOKEN)
        sh, fin = msgs
        self._parse_server_hello(sh)
        self._transcript += sh.raw
        self._derive_keys(self._pms)
        # Server Finished first, over ClientHello..ServerHello.
        expect = _p_sha256(
            self._master,
            b"server finished" + hashlib.sha256(self._transcript).digest(),
            _FINISHED_LEN,
        )
        assert self._recv is not None
        self._recv.seq = 0
        got = self._unwrap(self._recv, fin.value)
        if not hmac.compare_digest(got, expect):
            raise SncError("server Finished verification failed", major=_GSS_S_FAILURE)
        self._transcript += fin.raw
        finished = _tlv(_TAG_FINISHED, self._finished_token("client finished"))
        return _tlv_long2(0x30, _MECH_OID_TLV + _tlv_long2(_TAG_CONTAINER, finished))


def own_name_matches(credential: SncCredential, snc_name: str) -> bool:
    """True if ``snc_name`` names the certificate in ``credential``."""
    cert = _x509.Certificate.load(credential.certificate)
    return _names_match(parse_snc_name(snc_name), _cert_subject_rdns(cert))
