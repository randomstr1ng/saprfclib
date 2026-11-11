# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Kerberos encryption and checksum profiles for AES (RFC 3961, RFC 3962).

Implemented: ``aes128-cts-hmac-sha1-96`` (etype 17) and ``aes256-cts-hmac-sha1-96``
(etype 18) with their checksums ``hmac-sha1-96-aes128`` (15) and
``hmac-sha1-96-aes256`` (16). These are the enctypes Active Directory issues by
default for accounts with AES keys.

Not implemented, deliberately: RC4-HMAC (etype 23, needs MD4, deprecated), DES and
3DES (removed from current Kerberos implementations), and the RFC 8009 SHA-2
profiles (not supported by Active Directory).

The AES block cipher comes from ``tlslite-ng``; PBKDF2 and HMAC-SHA1 from the
standard library. What is built here is the RFC 3961 construction on top of those
primitives: n-fold, key derivation, ciphertext stealing and the encrypt/checksum
profile. Every piece is checked against the test vectors published in RFC 3961
Appendix A.1 and RFC 3962 Appendix B (``tests/test_krb5_crypto.py``).

Security: keys never appear in a ``repr`` or an exception message.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Callable
from dataclasses import dataclass, field

from tlslite.utils.cipherfactory import createAES

__all__ = [
    "ENCTYPE_AES128",
    "ENCTYPE_AES256",
    "CKSUMTYPE_HMAC_SHA1_96_AES128",
    "CKSUMTYPE_HMAC_SHA1_96_AES256",
    "IntegrityError",
    "Key",
    "checksum",
    "decrypt",
    "encrypt",
    "n_fold",
    "string_to_key",
    "verify_checksum",
]

# Encryption and checksum type numbers: RFC 3962 section 7.
ENCTYPE_AES128 = 17
ENCTYPE_AES256 = 18
CKSUMTYPE_HMAC_SHA1_96_AES128 = 15
CKSUMTYPE_HMAC_SHA1_96_AES256 = 16

_KEY_SIZE = {ENCTYPE_AES128: 16, ENCTYPE_AES256: 32}
_CKSUM_FOR_ENCTYPE = {
    ENCTYPE_AES128: CKSUMTYPE_HMAC_SHA1_96_AES128,
    ENCTYPE_AES256: CKSUMTYPE_HMAC_SHA1_96_AES256,
}
_ENCTYPE_FOR_CKSUM = {v: k for k, v in _CKSUM_FOR_ENCTYPE.items()}

_BLOCK = 16  # AES block size
_MAC_LEN = 12  # HMAC-SHA1 truncated to 96 bits (RFC 3962 section 6)
_DEFAULT_ITERATIONS = 4096  # RFC 3962 section 4: default s2kparams = 4096


class IntegrityError(Exception):
    """A ciphertext or checksum failed verification. Carries no key material."""


@dataclass(frozen=True)
class Key:
    """A Kerberos key: encryption type plus raw key bytes."""

    enctype: int
    contents: bytes = field(repr=False)

    def __post_init__(self) -> None:
        size = _KEY_SIZE.get(self.enctype)
        if size is None:
            raise ValueError(f"unsupported Kerberos encryption type {self.enctype}")
        if len(self.contents) != size:
            raise ValueError("key length does not match its encryption type")

    def __repr__(self) -> str:
        return f"Key(enctype={self.enctype}, <redacted>)"


# --- RFC 3961 section 5.1: n-fold ---------------------------------------------


def n_fold(data: bytes, nbytes: int) -> bytes:
    """RFC 3961 n-fold of ``data`` to ``nbytes`` bytes.

    The input is replicated lcm(len, n) / len times, each copy rotated right by 13
    bits more than the previous one, and the n-byte chunks are added with
    one's-complement (end-around carry) addition.
    """
    if not data or nbytes <= 0:
        raise ValueError("n-fold needs a non-empty input and a positive length")
    inbits = len(data) * 8
    lcm = len(data) * nbytes // _gcd(len(data), nbytes)
    value = int.from_bytes(data, "big")
    buf = bytearray()
    for i in range(lcm // len(data)):
        r = (13 * i) % inbits
        rotated = ((value >> r) | (value << (inbits - r))) & ((1 << inbits) - 1)
        buf += rotated.to_bytes(len(data), "big")
    total = 0
    mod = 1 << (nbytes * 8)
    for off in range(0, lcm, nbytes):
        total += int.from_bytes(buf[off : off + nbytes], "big")
        while total >= mod:  # one's-complement end-around carry
            total = (total & (mod - 1)) + (total >> (nbytes * 8))
    return total.to_bytes(nbytes, "big")


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# --- AES in CBC mode with ciphertext stealing (RFC 3962 section 5) -------------


def _cbc_encrypt(key: bytes, data: bytes) -> bytes:
    # A fresh cipher object per call: tlslite-ng's CBC object carries the chaining
    # value over from one call to the next.
    # tlslite-ng works on (and may modify) a bytearray: always hand it a copy.
    return bytes(createAES(key, bytes(_BLOCK)).encrypt(bytearray(data)))


def _cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return bytes(createAES(key, iv).decrypt(bytearray(data)))


def _cts_encrypt(key: bytes, data: bytes) -> bytes:
    """CBC-CS3 with a zero IV: the last two ciphertext blocks swapped, the final one
    truncated to the length of the last plaintext block."""
    if len(data) < _BLOCK:
        raise ValueError("CTS input shorter than one block")
    if len(data) == _BLOCK:
        return _cbc_encrypt(key, data)
    padded = data + bytes(-len(data) % _BLOCK)
    c = _cbc_encrypt(key, padded)
    n = len(padded) // _BLOCK
    head = c[: (n - 2) * _BLOCK]
    second_last = c[(n - 2) * _BLOCK : (n - 1) * _BLOCK]
    last = c[(n - 1) * _BLOCK :]
    return (head + last + second_last)[: len(data)]


def _cts_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) < _BLOCK:
        raise IntegrityError("ciphertext too short")
    if len(data) == _BLOCK:
        return _cbc_decrypt(key, bytes(_BLOCK), data)
    n = -(-len(data) // _BLOCK)
    r = len(data) - (n - 1) * _BLOCK  # bytes in the final (partial) block, 1..16
    head = data[: (n - 2) * _BLOCK]
    cn = data[(n - 2) * _BLOCK : (n - 1) * _BLOCK]  # sent second to last
    tail = data[(n - 1) * _BLOCK :]  # leading r bytes of C(n-1)
    x = _cbc_decrypt(key, bytes(_BLOCK), cn)  # = C(n-1) xor (P(n) || zero pad)
    c_prev = tail + x[r:]
    last_plain = bytes(a ^ b for a, b in zip(x[:r], tail, strict=True))
    iv = head[-_BLOCK:] if head else bytes(_BLOCK)
    # Decrypting C(n-1) chained on C(n-2) yields P(n-1); head yields P(1..n-2).
    front = _cbc_decrypt(key, bytes(_BLOCK), head) if head else b""
    p_prev = _cbc_decrypt(key, iv, c_prev)
    return front + p_prev + last_plain


# --- key derivation (RFC 3961 section 5.1, RFC 3962 section 4) -----------------


def _dr(key: bytes, constant: bytes) -> bytes:
    """DR(Key, Constant): iterate E over n-fold(Constant) until enough bytes."""
    block = n_fold(constant, _BLOCK) if len(constant) != _BLOCK else constant
    out = b""
    while len(out) < len(key):
        block = _cbc_encrypt(key, block)
        out += block
    return out[: len(key)]


def _dk(key: bytes, constant: bytes) -> bytes:
    # random-to-key is the identity for the AES enctypes (RFC 3962 section 6).
    return _dr(key, constant)


def string_to_key(
    enctype: int, password: str | bytes, salt: str | bytes, iterations: int | None = None
) -> Key:
    """RFC 3962 section 4: DK(random-to-key(PBKDF2-HMAC-SHA1(pw, salt)), "kerberos").

    ``iterations`` comes from the KDC's ``s2kparams`` when it sends them; the
    default is 4096.
    """
    size = _KEY_SIZE.get(enctype)
    if size is None:
        raise ValueError(f"unsupported Kerberos encryption type {enctype}")
    pw = password.encode("utf-8") if isinstance(password, str) else password
    s = salt.encode("utf-8") if isinstance(salt, str) else salt
    tkey = hashlib.pbkdf2_hmac("sha1", pw, s, iterations or _DEFAULT_ITERATIONS, size)
    return Key(enctype, _dk(tkey, b"kerberos"))


def _usage_key(key: Key, usage: int, tag: int) -> bytes:
    # Ke = DK(base, usage | 0xAA), Ki = DK(base, usage | 0x55), Kc = DK(base, usage | 0x99)
    return _dk(key.contents, usage.to_bytes(4, "big") + bytes([tag]))


# --- encryption profile (RFC 3961 section 5.3, RFC 3962 section 6) -------------


def encrypt(
    key: Key,
    usage: int,
    plaintext: bytes,
    *,
    confounder: bytes | None = None,
    random: Callable[[int], bytes] = os.urandom,
) -> bytes:
    """Encrypt ``plaintext`` for key usage ``usage``: CTS(Ke, conf | P) || HMAC(Ki)[:12].

    ``confounder`` is injectable for test vectors; normally it is random.
    """
    conf = confounder if confounder is not None else random(_BLOCK)
    if len(conf) != _BLOCK:
        raise ValueError("confounder must be one block")
    basic = conf + plaintext
    ke = _usage_key(key, usage, 0xAA)
    ki = _usage_key(key, usage, 0x55)
    mac = hmac.new(ki, basic, hashlib.sha1).digest()[:_MAC_LEN]
    return _cts_encrypt(ke, basic) + mac


def decrypt(key: Key, usage: int, ciphertext: bytes) -> bytes:
    """Inverse of :func:`encrypt`; raises :class:`IntegrityError` on any mismatch."""
    if len(ciphertext) < _BLOCK + _MAC_LEN:
        raise IntegrityError("ciphertext too short")
    body, mac = ciphertext[:-_MAC_LEN], ciphertext[-_MAC_LEN:]
    ke = _usage_key(key, usage, 0xAA)
    ki = _usage_key(key, usage, 0x55)
    basic = _cts_decrypt(ke, body)
    want = hmac.new(ki, basic, hashlib.sha1).digest()[:_MAC_LEN]
    if not hmac.compare_digest(want, mac):
        raise IntegrityError("Kerberos ciphertext integrity check failed")
    return basic[_BLOCK:]


# --- checksum profile (RFC 3961 section 5.4) -----------------------------------


def checksum(key: Key, usage: int, data: bytes) -> tuple[int, bytes]:
    """Keyed checksum: (cksumtype, HMAC-SHA1(Kc, data)[:12])."""
    kc = _usage_key(key, usage, 0x99)
    return _CKSUM_FOR_ENCTYPE[key.enctype], hmac.new(kc, data, hashlib.sha1).digest()[:_MAC_LEN]


def verify_checksum(key: Key, usage: int, data: bytes, cksumtype: int, value: bytes) -> None:
    if _ENCTYPE_FOR_CKSUM.get(cksumtype) != key.enctype:
        raise IntegrityError("checksum type does not match the key")
    _, want = checksum(key, usage, data)
    if not hmac.compare_digest(want, value):
        raise IntegrityError("Kerberos checksum verification failed")
