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
* X.509 authentication of both sides with RSA PKCS#1 v1.5 signatures.

Anything else the peer selects is refused with :class:`~saprfclib.exceptions.SncError`
rather than attempted.

Crypto primitives come from maintained third-party pure-Python libraries — AES from
``tlslite-ng``, RSA from ``tlslite-ng``, ECDH from ``ecdsa``, certificate and key
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
from ecdsa import ECDH, NIST256p
from tlslite.utils.cipherfactory import createAES
from tlslite.utils.python_rsakey import Python_RSAKey

from saprfclib.exceptions import SncError

__all__ = [
    "GSS_S_COMPLETE",
    "GSS_S_CONTINUE_NEEDED",
    "SncCredential",
    "SecGssInitiator",
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
# fixture secgss_handshake_q3 (ClientHello params, ServerHello params
# 01 01 0009 00004000).
_VERSION_1_1 = (1, 1)
_MAC_HMAC_SHA256 = 1
_CIPHER_AES256 = 1
_HS_HASH_SHA256 = 2
_PRF_PHASH_SHA256 = 2
_ENCODING_DATA_HEADER_V1 = 2
_KEX_SERVER_ECDHE = 4
_SUITE_ECDHE_P256_AES256_SHA256 = 0x0009

# Hello extension ids. 3 = client cipher-suite list (BE u16 ids), 5 = NULL flag
# sent by the reference client. Source: golden fixture ClientHello extensions.
_EXT_CLIENT_CIPHER_SUITES = 3
_EXT_CLIENT_IS_NOT_SLC = 5

# Signature algorithm ids carried in AuthRequest (BE u32). Source: golden fixture
# AuthRequest lists; the server answered with sha512WithRSAEncryption when 0x01000601
# was listed first.
_SIGALG_RSA_PKCS1_SHA512 = 0x01000601
_SIGALG_RSA_PKCS1_SHA256 = 0x01000201
_SIGALG_HASH: dict[int, str] = {
    _SIGALG_RSA_PKCS1_SHA512: "sha512",
    _SIGALG_RSA_PKCS1_SHA256: "sha256",
}
# X.509 AlgorithmIdentifier for each, DER (OID + NULL parameters, as observed).
_SIGALG_ALGID: dict[int, bytes] = {
    _SIGALG_RSA_PKCS1_SHA512: bytes.fromhex("300d06092a864886f70d01010d0500"),
    _SIGALG_RSA_PKCS1_SHA256: bytes.fromhex("300d06092a864886f70d01010b0500"),
}
_ALGID_OID_TO_SIGALG: dict[str, int] = {
    "1.2.840.113549.1.1.13": _SIGALG_RSA_PKCS1_SHA512,
    "1.2.840.113549.1.1.11": _SIGALG_RSA_PKCS1_SHA256,
}
# What we offer the server for *its* signature, most preferred first.
_OFFERED_SIGALGS = (_SIGALG_RSA_PKCS1_SHA512, _SIGALG_RSA_PKCS1_SHA256)

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
    container this way regardless of size (golden fixture secgss_handshake_q3).
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
    golden fixture secgss_session_q3 — master secret, both key blocks and both
    Finished values recompute from the recorded inputs with this function.
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
    golden fixture secgss_session_q3 — every record of both directions, server
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
    # Source: golden fixture secgss_session_q3 (recomputed MAC inputs).
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

# X.500 attribute abbreviations → OIDs (standard X.520 / RFC 4519 assignments).
_ATTR_OIDS: dict[str, str] = {
    "CN": "2.5.4.3",
    "SN": "2.5.4.4",
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


def _rsa_private(der: bytes) -> Python_RSAKey:
    try:
        info = _keys.PrivateKeyInfo.load(der)
        if info.algorithm != "rsa":
            raise SncError("own key is not an RSA key; only RSA keys are supported")
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
        raise SncError("peer certificate key is not RSA; only RSA peers are supported")
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
    """True if ``issuer`` names and RSA-PKCS#1-v1.5-signs ``child``."""
    if child.issuer != issuer.subject:
        return False
    algo = child["signature_algorithm"]
    try:
        if algo.signature_algo != "rsassa_pkcs1v15":
            return False
        h = algo.hash_algo
    except ValueError:
        return False
    if h not in _CERT_SIG_HASHES:
        return False
    try:
        key = _rsa_public(issuer)
    except SncError:
        return False
    tbs = child["tbs_certificate"].dump()
    sig = child["signature_value"].native
    return bool(key.hashAndVerify(bytearray(sig), bytearray(tbs), "PKCS1", h))


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

    Trusted means: the leaf itself is one of ``trusted``, or a chain of RSA
    signatures over certificates the peer sent leads to one of ``trusted``. Expiry
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


class SecGssInitiator:
    """Client side of the mechanism; drop-in for :class:`saprfclib.snc.GssBinding`.

    ``init_sec_context`` is called with the peer's last token (``b""`` first) and
    returns ``(major, output_token)`` exactly like ``gss_init_sec_context``:
    ``CONTINUE_NEEDED`` twice, then ``COMPLETE`` with an empty output token.

    ``random`` and ``clock`` exist for deterministic replay in tests; production
    callers leave them at their defaults (``os.urandom``, ``time.time``).
    ``ecdh_private_key`` likewise pins the ephemeral scalar for replay only, and
    ``signer`` replaces signing with the credential's private key (it receives the
    data to sign and the hash name, and returns an RSA PKCS#1 v1.5 signature).
    """

    # Attributes SncTransport reads on a binding.
    _real = False
    _lib: Any = None

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
        self._random = random
        self._clock = clock
        self._ecdh_fixed = ecdh_private_key
        if signer is None:
            rsa = _rsa_private(credential.private_key)

            def signer(data: bytes, hash_name: str) -> bytes:
                return bytes(rsa.hashAndSign(bytearray(data), "PKCS1", hash_name))

        self._sign: Signer = signer
        self._own_cert = _x509.Certificate.load(credential.certificate)
        if self._own_cert.public_key.algorithm != "rsa":
            raise SncError("own certificate key is not RSA; only RSA keys are supported")
        self._step = 0
        self._transcript = bytearray()
        self._client_random = b""
        self._server_random = b""
        self._server_sigalgs: list[int] = []
        self._ecdh: ECDH | None = None
        self._master = b""
        self._send: _Direction | None = None
        self._recv: _Direction | None = None
        self._chunk_size = 0
        self.peer_certificate: bytes | None = None
        self.established = False

    # -- GssBinding surface ------------------------------------------------

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

    # -- record layer --------------------------------------------------------

    def _chunks(self, payload: bytes) -> list[bytes]:
        size = self._chunk_size
        return [payload[i : i + size] for i in range(0, len(payload), size)] or [b""]

    def _wrap(self, d: _Direction, payload: bytes) -> bytes:
        body = bytearray()
        for i, chunk in enumerate(self._chunks(payload)):
            # Pad value is the pad length itself, 1..16 bytes; padding is inside the
            # MAC (MAC-then-encrypt). Source: golden fixture secgss_session_q3.
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

    # -- handshake -------------------------------------------------------------

    def _require_established(self) -> None:
        if not self.established:
            raise SncError("SNC security context is not established")

    def _discard_handshake_state(self) -> None:
        self._ecdh = None
        self._master = b""
        self._transcript = bytearray()

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

    def _token1(self) -> bytes:
        # random = BE32 seconds since the epoch || 28 random bytes.
        self._client_random = struct.pack(">I", int(self._clock()) & 0xFFFFFFFF) + self._random(28)
        params = (
            bytes([2]) + bytes(_VERSION_1_1)
            + bytes([1, _MAC_HMAC_SHA256])
            + bytes([1, _CIPHER_AES256])
            + bytes([1, _HS_HASH_SHA256])
            + bytes([1, _PRF_PHASH_SHA256])
            + bytes([1, _ENCODING_DATA_HEADER_V1])
            + bytes([1, _KEX_SERVER_ECDHE])
        )  # fmt: skip
        ext_suites = _tlv(
            0x30,
            _der_int(_EXT_CLIENT_CIPHER_SUITES)
            + _tlv(0x04, struct.pack(">H", _SUITE_ECDHE_P256_AES256_SHA256)),
        )
        ext_not_slc = _tlv(0x30, _der_int(_EXT_CLIENT_IS_NOT_SLC) + b"\x05\x00")
        hello = _tlv(
            _TAG_CLIENT_HELLO,
            _tlv(0x04, params)
            + _tlv(0x04, self._client_random)
            + _tlv(0xA1, ext_suites + ext_not_slc),
        )
        return self._emit([hello])

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

        sigalg = next((a for a in self._server_sigalgs if a in _SIGALG_HASH), None)
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
        if not _verify_rsa(_rsa_public(leaf), sigalg, signature, bytes(self._transcript)):
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

    # -- message parsers -------------------------------------------------------

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
        if suite != _SUITE_ECDHE_P256_AES256_SHA256:
            raise SncError("server selected an unsupported SNC cipher suite")
        if chunk == 0 or chunk > _MAX_TOKEN_BYTES:
            raise SncError("server announced an invalid chunk size")
        self._server_random = rnd
        self._chunk_size = chunk

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


def own_name_matches(credential: SncCredential, snc_name: str) -> bool:
    """True if ``snc_name`` names the certificate in ``credential``."""
    cert = _x509.Certificate.load(credential.certificate)
    return _names_match(parse_snc_name(snc_name), _cert_subject_rdns(cert))
