# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Readers for MIT-format credential caches and keytabs.

Formats as published by MIT Kerberos ("Credential cache file format", "Keytab file
format" in the MIT krb5 documentation). Supported: ccache versions 3 and 4 and
keytab version 2 — the big-endian versions every current MIT and Heimdal release
writes. Versions 1 and 2 of the ccache format and version 1 of the keytab format
use the writer's native byte order and are refused rather than guessed at.

Only FILE ccaches can be read. ``KEYRING:``, ``KCM:``, ``API:`` and ``MSLSA:``
caches live in the kernel, a daemon or the OS and are not reachable from pure
Python; :func:`default_ccache_path` reports them as unsupported.

Entries whose encryption type this library does not implement (see
:mod:`saprfclib.krb5.crypto`) are kept but carry no usable key: ``key`` is None.
"""

from __future__ import annotations

import datetime as _dt
import os
import struct
from dataclasses import dataclass, field

from saprfclib.krb5.client import Credential, Principal
from saprfclib.krb5.crypto import Key

__all__ = [
    "CredentialCacheError",
    "KeytabEntry",
    "default_ccache_path",
    "read_ccache",
    "read_keytab",
]

_CONF_REALM = "X-CACHECONF:"  # configuration entries, MIT ccache format docs


class CredentialCacheError(Exception):
    """A ccache or keytab file is malformed or uses an unsupported version."""


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.d):
            raise CredentialCacheError("file is truncated")
        b = self.d[self.i : self.i + n]
        self.i += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int(struct.unpack(">H", self.take(2))[0])

    def u32(self) -> int:
        return int(struct.unpack(">I", self.take(4))[0])

    def s32(self) -> int:
        return int(struct.unpack(">i", self.take(4))[0])

    def data32(self) -> bytes:
        return self.take(self.u32())

    def data16(self) -> bytes:
        return self.take(self.u16())

    def done(self) -> bool:
        return self.i >= len(self.d)


def _text(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CredentialCacheError("principal name is not UTF-8") from e


def _time(v: int) -> _dt.datetime | None:
    return _dt.datetime.fromtimestamp(v, _dt.UTC) if v else None


def _key_or_none(enctype: int, contents: bytes) -> Key | None:
    try:
        return Key(enctype, contents)
    except ValueError:
        return None


# --- credential cache ----------------------------------------------------------


def _cc_principal(r: _Reader) -> Principal:
    name_type = r.u32()
    count = r.u32()
    realm = _text(r.data32())
    comps = tuple(_text(r.data32()) for _ in range(count))
    return Principal(comps, realm, name_type)


def read_ccache(data: bytes) -> tuple[Principal, list[Credential]]:
    """Parse a FILE ccache: (default principal, usable credentials).

    Configuration entries, entries with an unsupported session-key type and
    user-to-user (``is_skey``) entries are skipped.
    """
    r = _Reader(data)
    if r.u8() != 5:
        raise CredentialCacheError("not a Kerberos credential cache")
    version = r.u8()
    if version not in (3, 4):
        raise CredentialCacheError(f"credential cache version {version} is not supported")
    if version == 4:
        hdr = _Reader(r.take(r.u16()))
        while not hdr.done():
            hdr.u16()
            hdr.data16()  # tag 1 = KDC time offset; not needed (we take KDC times)
    default = _cc_principal(r)
    creds: list[Credential] = []
    while not r.done():
        client = _cc_principal(r)
        server = _cc_principal(r)
        enctype = r.u16()
        if version == 3:
            r.u16()  # enctype repeated in version 3
        keyval = r.data32()
        authtime, starttime, endtime, renew = r.u32(), r.u32(), r.u32(), r.u32()
        is_skey = r.u8()
        flags = r.take(4)
        for _ in range(r.u32()):  # addresses
            r.u16()
            r.data32()
        for _ in range(r.u32()):  # authdata
            r.u16()
            r.data32()
        ticket = r.data32()
        r.data32()  # second ticket
        if server.realm == _CONF_REALM or is_skey:
            continue
        key = _key_or_none(enctype, keyval)
        if key is None:
            continue
        creds.append(
            Credential(
                client=client,
                server=server,
                ticket=ticket,
                session_key=key,
                flags=flags,
                authtime=_time(authtime) or _dt.datetime.fromtimestamp(0, _dt.UTC),
                starttime=_time(starttime),
                endtime=_time(endtime) or _dt.datetime.fromtimestamp(0, _dt.UTC),
                renew_till=_time(renew),
            )
        )
    return default, creds


def default_ccache_path() -> str:
    """Path of the default FILE ccache: ``KRB5CCNAME``, else ``/tmp/krb5cc_<uid>``.

    Raises :class:`CredentialCacheError` for cache types that are not files. The
    ``/tmp/krb5cc_<uid>`` fallback is MIT's built-in default on Unix; a system that
    sets a different ``default_ccache_name`` in ``krb5.conf`` must export
    ``KRB5CCNAME`` (or pass the path) — ``krb5.conf`` is not parsed.
    """
    name = os.environ.get("KRB5CCNAME")
    if name:
        kind, sep, rest = name.partition(":")
        if not sep or (len(kind) == 1 and os.name == "nt"):  # bare path / drive letter
            return name
        if kind.upper() == "FILE":
            return rest
        raise CredentialCacheError(
            f"credential cache type {kind.upper()}: cannot be read; use a FILE: cache"
        )
    if not hasattr(os, "getuid"):
        # Windows keeps logon tickets in LSA, which is not a file.
        raise CredentialCacheError(
            "no KRB5CCNAME set; Windows logon tickets cannot be read — pass "
            "KerberosLogin(principal=..., password=... or keytab=...) or a FILE ccache"
        )
    return f"/tmp/krb5cc_{os.getuid()}"


# --- keytab --------------------------------------------------------------------


@dataclass(frozen=True)
class KeytabEntry:
    principal: Principal
    timestamp: _dt.datetime | None
    kvno: int
    enctype: int
    key: Key | None = field(repr=False)


def read_keytab(data: bytes) -> list[KeytabEntry]:
    r = _Reader(data)
    if r.u8() != 5:
        raise CredentialCacheError("not a Kerberos keytab")
    version = r.u8()
    if version != 2:
        raise CredentialCacheError(f"keytab version {version} is not supported")
    out: list[KeytabEntry] = []
    while not r.done():
        if len(r.d) - r.i < 4:
            break
        size = r.s32()
        if size == 0:
            break
        if size < 0:
            r.take(-size)  # hole
            continue
        rec = _Reader(r.take(size))
        count = rec.u16()
        realm = _text(rec.data16())
        comps = tuple(_text(rec.data16()) for _ in range(count))
        name_type = rec.u32()
        ts = rec.u32()
        kvno = rec.u8()
        enctype = rec.u16()
        keyval = rec.data16()
        if len(rec.d) - rec.i >= 4:
            kvno32 = rec.u32()
            if kvno32:
                kvno = kvno32
        out.append(
            KeytabEntry(
                Principal(comps, realm, name_type),
                _time(ts),
                kvno,
                enctype,
                _key_or_none(enctype, keyval),
            )
        )
    return out
