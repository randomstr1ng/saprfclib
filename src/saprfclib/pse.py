# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Read a CommonCryptoLib PSE file into an :class:`~saprfclib.secgss.SncCredential`.

A PSE ("personal security environment") holds the own private key, the own
certificate, its issuer chain and the list of trusted certificates. This reader
supports the two container versions written by ``sapgenpse`` (2 and 4), PIN
protected with either PKCS#12 ``pbeWithSHAAnd3-KeyTripleDES-CBC`` (the default)
or PBES2 / PBKDF2 / AES-256-CBC, and unprotected PSEs.

Every layout detail below is checked by the golden PSE files under
``tests/golden/pse/``, created with ``sapgenpse`` and paired with the key and
certificates ``sapgenpse`` itself exported from them.

Not supported (refused with :class:`PseError`): PSEs wrapped in local protected
storage (container version 0x100) and PIN retrieval from ``cred_v2`` files — pass
the PIN explicitly.

Security: neither the PIN nor key material ever enters a log or an exception
message.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from asn1crypto import core as _core
from asn1crypto import keys as _keys
from tlslite.utils.cipherfactory import createAES, createTripleDES

from saprfclib.exceptions import SncError
from saprfclib.secgss import SncCredential

__all__ = ["PseError", "load_pse"]


class PseError(SncError):
    """A PSE file could not be read: wrong PIN, unsupported variant or corrupt file."""


# Object names inside a PSE. Source: golden PSE files (tests/golden/pse/*.json).
_OBJ_PRIVATE_KEY = "SKnew"
_OBJ_CERT = "Cert"
_OBJ_TRUSTED = "PKList"
_OBJ_CHAIN = "FCPath"
_OBJ_ROOT = "PKRoot"

_OID_PBE_SHA1_3DES = "1.2.840.113549.1.12.1.3"
_OID_PBES2 = "1.2.840.113549.1.5.13"
_OID_PBKDF2 = "1.2.840.113549.1.5.12"
_OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"
_OID_RSA = "1.2.840.113549.1.1.1"
_HMAC_PRF = {
    "1.2.840.113549.2.7": "sha1",
    "1.2.840.113549.2.9": "sha256",
    "1.2.840.113549.2.11": "sha512",
}


# ---------------------------------------------------------------------------
# DER walking (definite lengths)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _T:
    tag: int
    value: bytes
    raw: bytes

    def kids(self) -> list[_T]:
        out: list[_T] = []
        pos = 0
        while pos < len(self.value):
            t, pos = _read(self.value, pos)
            out.append(t)
        return out

    def int(self) -> int:
        return int.from_bytes(self.value, "big", signed=True)

    def oid(self) -> str:
        return str(_core.ObjectIdentifier.load(self.raw).dotted)


def _read(buf: bytes, pos: int = 0) -> tuple[_T, int]:
    try:
        tag = buf[pos]
        n = buf[pos + 1]
        i = pos + 2
        if n & 0x80:
            k = n & 0x7F
            if not 0 < k <= 4:
                raise PseError("unsupported length encoding in PSE")
            n = int.from_bytes(buf[i : i + k], "big")
            i += k
    except IndexError:
        raise PseError("truncated PSE") from None
    end = i + n
    if end > len(buf):
        raise PseError("truncated PSE")
    return _T(tag, buf[i:end], buf[pos:end]), end


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


# ---------------------------------------------------------------------------
# Password-based decryption
# ---------------------------------------------------------------------------


def _pkcs12_kdf(password: bytes, salt: bytes, purpose: int, iterations: int, n: int) -> bytes:
    """RFC 7292 Appendix B.2 key derivation with SHA-1."""
    u, v = 20, 64

    def stretch(x: bytes) -> bytes:
        if not x:
            return b""
        size = v * ((len(x) + v - 1) // v)
        return (x * (size // len(x) + 1))[:size]

    d = bytes([purpose]) * v
    buf = bytearray(stretch(salt) + stretch(password))
    out = bytearray()
    while len(out) < n:
        a = d + bytes(buf)
        for _ in range(iterations):
            a = hashlib.sha1(a).digest()
        out += a
        b = int.from_bytes((a * (v // u + 1))[:v], "big")
        for j in range(0, len(buf), v):
            x = (int.from_bytes(buf[j : j + v], "big") + b + 1) % (1 << (8 * v))
            buf[j : j + v] = x.to_bytes(v, "big")
    return bytes(out[:n])


def _cipher(algid: _T, pin: str) -> tuple[str, bytes, bytes]:
    """Return (cipher name, key, iv) for a PSE's PBE AlgorithmIdentifier."""
    parts = algid.kids()
    oid = parts[0].oid()
    if oid == _OID_PBE_SHA1_3DES:
        salt, it = parts[1].kids()[:2]
        # PKCS#12 passwords are BMPString (UTF-16BE) with a two-byte terminator.
        pw = (pin + "\0").encode("utf-16-be") if pin else b""
        count = it.int()
        return (
            "3des",
            _pkcs12_kdf(pw, salt.value, 1, count, 24),
            _pkcs12_kdf(pw, salt.value, 2, count, 8),
        )
    if oid == _OID_PBES2:
        kdf, enc = parts[1].kids()[:2]
        kdf_oid, kdf_params = kdf.kids()[:2]
        if kdf_oid.oid() != _OID_PBKDF2:
            raise PseError("unsupported PSE key derivation")
        kp = kdf_params.kids()
        salt_b, count = kp[0].value, kp[1].int()
        prf, keylen = "sha1", 32
        for x in kp[2:]:
            if x.tag == 0x02:
                keylen = x.int()
            elif x.tag == 0x30:
                prf_oid = x.kids()[0].oid()
                if prf_oid not in _HMAC_PRF:
                    raise PseError("unsupported PSE key derivation")
                prf = _HMAC_PRF[prf_oid]
        enc_oid, iv = enc.kids()[:2]
        if enc_oid.oid() != _OID_AES256_CBC or keylen != 32:
            raise PseError("unsupported PSE encryption")
        return "aes", hashlib.pbkdf2_hmac(prf, pin.encode("utf-8"), salt_b, count, 32), iv.value
    raise PseError("unsupported PSE encryption")


def _cbc(name: str, key: bytes, iv: bytes, data: bytes, *, decrypt: bool) -> bytes:
    factory = createAES if name == "aes" else createTripleDES
    c = factory(bytearray(key), bytearray(iv))
    return bytes(c.decrypt(bytearray(data)) if decrypt else c.encrypt(bytearray(data)))


def _pad(data: bytes, bs: int) -> bytes:
    n = bs - len(data) % bs
    return data + bytes([n]) * n


def _unpad(data: bytes, bs: int) -> bytes:
    if not data or len(data) % bs:
        raise PseError("cannot decrypt PSE (wrong PIN?)")
    n = data[-1]
    if not 1 <= n <= bs or data[-n:] != bytes([n]) * n:
        raise PseError("cannot decrypt PSE (wrong PIN?)")
    return data[:-n]


def _block(name: str) -> int:
    return 16 if name == "aes" else 8


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------


def _objects(plain: bytes) -> dict[str, _T]:
    """PSE content: SEQUENCE { ..., SET OF SEQUENCE { name, time, oid, value, ... } }."""
    content, _ = _read(plain)
    sets = [k for k in content.kids() if k.tag == 0x31]
    if len(sets) != 1:
        raise PseError("unrecognised PSE content")
    out: dict[str, _T] = {}
    for obj in sets[0].kids():
        fields = obj.kids()
        if len(fields) < 4:
            raise PseError("unrecognised PSE object")
        out[fields[0].value.decode("latin-1")] = fields[3]
    return out


def _rsa_from_primes(p: int, q: int, n: int, e: int) -> bytes:
    if p * q != n:
        raise PseError("PSE private key does not match its certificate")
    d = pow(e, -1, (p - 1) * (q - 1))
    ints = (0, n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p))
    rsa = _keys.RSAPrivateKey(
        {
            "version": ints[0],
            "modulus": ints[1],
            "public_exponent": ints[2],
            "private_exponent": ints[3],
            "prime1": ints[4],
            "prime2": ints[5],
            "exponent1": ints[6],
            "exponent2": ints[7],
            "coefficient": ints[8],
        }
    )
    return bytes(rsa.dump())


def _private_key(sk: _T, cert: bytes) -> bytes:
    """Private key object → PKCS#1 RSAPrivateKey DER (RSA only).

    The PSE stores RSA keys either as a full PKCS#1 structure or in a compact
    ``SEQUENCE { p, q }`` form; the latter is completed from the certificate's
    public key.
    """
    alg, bits = sk.kids()[:2]
    if alg.kids()[0].oid() != _OID_RSA:
        raise PseError("PSE key is not an RSA key; only RSA keys are supported")
    key, _ = _read(bits.value[1:])
    ints = [k.int() for k in key.kids()]
    if len(ints) == 2:
        from asn1crypto import x509

        pub = x509.Certificate.load(cert).public_key["public_key"].parsed
        return _rsa_from_primes(
            ints[0], ints[1], pub["modulus"].native, pub["public_exponent"].native
        )
    return key.raw


def _root_certificate(pk: _T) -> bytes:
    """Rebuild the X.509 certificate a PSE stores in compact root form.

    Layout: SEQUENCE { DName, SEQUENCE { [0] version?, serial, SPKI, [1] validity,
    [2] signature algorithm, BIT STRING signature }, [0] extensions? }; issuer and
    subject are both the DName. The result is byte-identical to the imported
    certificate (golden PSE fixture with a CA chain).
    """
    dn, body, *rest = pk.kids()
    b = body.kids()
    i = 1 if b[0].tag == 0xA0 else 0
    version = b[0].raw if i else b""
    serial, spki, validity, sigalg, sig = b[i : i + 5]
    ext = _der(0xA3, rest[0].value) if rest and rest[0].tag == 0xA0 else b""
    tbs = _der(
        0x30,
        version + serial.raw + sigalg.value + dn.raw + validity.value + dn.raw + spki.raw + ext,
    )
    return _der(0x30, tbs + sigalg.value + sig.raw)


def load_pse(data: bytes, pin: str | None) -> SncCredential:
    """Parse a PSE file's bytes into an :class:`SncCredential`.

    Raises:
        PseError: wrong PIN, unsupported PSE variant, or corrupt file.
    """
    outer, _ = _read(data)
    kids = outer.kids()
    if len(kids) < 2 or kids[0].tag != 0x02:
        raise PseError("not a PSE file")
    version = kids[0].int()
    body = kids[1]
    if version == 0x100:
        raise PseError(
            "PSE is wrapped in local protected storage, which is not supported; "
            "re-create it without LPS (sapgenpse ... -noreqlps / lps off)"
        )
    if version == 2:
        if body.tag == 0x30:
            plain = body.raw
        elif body.tag == 0xA0:
            verifier, algid, ct = body.kids()[:3]
            if pin is None:
                raise PseError("PSE is PIN protected; a PIN is required")
            name, key, iv = _cipher(algid, pin)
            # The verifier is the PIN encrypted under the same parameters.
            check = _cbc(name, key, iv, _pad(pin.encode("utf-8"), _block(name)), decrypt=False)
            if check != verifier.value:
                raise PseError("wrong PSE PIN")
            plain = _unpad(_cbc(name, key, iv, ct.value, decrypt=True), _block(name))
        else:
            raise PseError("unrecognised PSE version 2 body")
    elif version == 4:
        flags_t, algid, ct, digest = body.kids()[:4]
        flags = flags_t.int()
        if flags & ~1:
            raise PseError("unsupported PSE version 4 flags")
        if flags & 1:
            if pin is None:
                raise PseError("PSE is PIN protected; a PIN is required")
            name, key, iv = _cipher(algid, pin)
            plain = _unpad(_cbc(name, key, iv, ct.value, decrypt=True), _block(name))
        else:
            plain = ct.value
        if hashlib.sha1(plain).digest() != digest.value:
            raise PseError("PSE integrity check failed (wrong PIN?)")
    else:
        raise PseError("unsupported PSE version")

    objs = _objects(plain)
    if _OBJ_CERT not in objs or _OBJ_PRIVATE_KEY not in objs:
        raise PseError("PSE has no own certificate and private key")
    own = objs[_OBJ_CERT].raw
    chain: list[bytes] = [own]
    if _OBJ_CHAIN in objs:
        for s in objs[_OBJ_CHAIN].kids():
            chain += [c.raw for c in s.kids()] if s.tag == 0x31 else [s.raw]
    if _OBJ_ROOT in objs:
        root = _root_certificate(objs[_OBJ_ROOT])
        if root not in chain:
            chain.append(root)
    trusted = tuple(c.raw for c in objs[_OBJ_TRUSTED].kids()) if _OBJ_TRUSTED in objs else ()
    return SncCredential(
        private_key=_private_key(objs[_OBJ_PRIVATE_KEY], own),
        certificate_chain=tuple(chain),
        trusted=trusted,
    )
