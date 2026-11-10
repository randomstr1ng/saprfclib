# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Getting a service ticket for Kerberos SNC.

:class:`KerberosLogin` says where the client's Kerberos identity comes from:

* nothing (the default) — the FILE credential cache named by ``KRB5CCNAME`` (or
  MIT's default path), as left by ``kinit`` or a desktop login;
* ``ccache`` — an explicit credential cache file;
* ``principal`` + ``password`` — an AS exchange with the KDC;
* ``principal`` + ``keytab`` — an AS exchange with a key from a keytab file.

A service ticket already in the cache is used as is. Otherwise the ticket-granting
ticket is used for a TGS exchange, which needs a KDC: ``kdc`` if given, else the
``kdc`` entries for the realm in ``krb5.conf`` (``KRB5_CONFIG``, else
``/etc/krb5.conf``). Nothing else is assumed; with no KDC known the call fails with
an error naming the realm.

Only the client's own realm is supported (no cross-realm referrals).

Security: passwords, keys and tickets never reach a log record, a ``repr`` or an
exception message.
"""

from __future__ import annotations

import datetime as _dt
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from saprfclib.krb5.client import (
    AsExchange,
    Credential,
    KerberosError,
    Principal,
    TgsExchange,
    kdc_roundtrip,
)
from saprfclib.krb5.files import default_ccache_path, read_ccache, read_keytab

__all__ = ["KerberosLogin", "kdcs_from_krb5_conf", "obtain_service_ticket"]

_KDC_PORT = 88  # RFC 4120 section 7.2.3: the "kerberos" port, 88
# A ticket that expires within this margin is not reused from a cache: the server
# checks the end time against its own clock.
_EXPIRY_MARGIN = _dt.timedelta(minutes=5)


@dataclass(frozen=True)
class KerberosLogin:
    """Where the Kerberos identity for SNC comes from. See the module docstring."""

    principal: str | None = None
    password: str | None = field(default=None, repr=False)
    keytab: str | os.PathLike[str] | None = None
    ccache: str | os.PathLike[str] | None = None
    kdc: str | None = None

    def __post_init__(self) -> None:
        sources = sum(x is not None for x in (self.password, self.keytab, self.ccache))
        if sources > 1:
            raise ValueError("pass at most one of password, keytab or ccache")
        if (self.password is not None or self.keytab is not None) and not self.principal:
            raise ValueError("a password or keytab login needs the client principal")


def _parse_kdc(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if sep and port.isdigit() and "]" not in port:
        return host.strip("[]"), int(port)
    return text.strip("[]"), _KDC_PORT


def kdcs_from_krb5_conf(realm: str, path: str | None = None) -> list[tuple[str, int]]:
    """The ``kdc`` entries of ``realm`` in a krb5.conf ``[realms]`` section."""
    path = path or os.environ.get("KRB5_CONFIG", "/etc/krb5.conf").split(":")[0]
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    out: list[tuple[str, int]] = []
    section = ""
    current: str | None = None
    depth = 0
    for raw in lines:
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section, current, depth = line[1:-1].strip().lower(), None, 0
            continue
        if section != "realms":
            continue
        if line.endswith("{"):
            if depth == 0:
                current = line[:-1].split("=", 1)[0].strip()
            depth += 1
            continue
        if line == "}":
            depth = max(depth - 1, 0)
            if depth == 0:
                current = None
            continue
        if depth == 1 and current == realm and "=" in line:
            key, value = (p.strip() for p in line.split("=", 1))
            if key.lower() == "kdc" and value:
                out.append(_parse_kdc(value))
    return out


def _kdcs(login: KerberosLogin, realm: str) -> list[tuple[str, int]]:
    if login.kdc:
        return [_parse_kdc(login.kdc)]
    found = kdcs_from_krb5_conf(realm)
    if not found:
        raise KerberosError(
            f"no KDC known for realm {realm}: pass KerberosLogin(kdc=...) or list it in krb5.conf"
        )
    return found


def _ask(kdcs: list[tuple[str, int]], request: bytes, timeout: float) -> bytes:
    last: Exception | None = None
    for kdc in kdcs:
        try:
            return kdc_roundtrip(kdc, request, timeout=timeout)
        except (OSError, KerberosError) as e:  # try the next KDC, as clients do
            last = e
    raise KerberosError("no KDC could be reached") from last


def _valid(cred: Credential, now: _dt.datetime) -> bool:
    start = cred.starttime or cred.authtime
    return start - _EXPIRY_MARGIN <= now and cred.endtime - _EXPIRY_MARGIN > now


def _same(a: Principal, b: Principal) -> bool:
    # Realms compare exactly (RFC 4120 6.1); name components exactly as well, except
    # that AD treats user names case-insensitively and canonicalizes them.
    return a.realm.upper() == b.realm.upper() and [c.lower() for c in a.components] == [
        c.lower() for c in b.components
    ]


def obtain_service_ticket(
    login: KerberosLogin,
    service: Principal,
    *,
    timeout: float = 10.0,
    clock: Callable[[], float] = time.time,
) -> Credential:
    """Return a ticket for ``service`` following the rules in the module docstring."""
    now = _dt.datetime.fromtimestamp(clock(), _dt.UTC)
    if login.password is not None or login.keytab is not None:
        assert login.principal is not None
        client = Principal.parse(login.principal)
        keys = []
        if login.keytab is not None:
            with open(login.keytab, "rb") as fh:
                keys = [
                    e.key
                    for e in read_keytab(fh.read())
                    if e.key is not None and _same(e.principal, client)
                ]
            if not keys:
                raise KerberosError("the keytab holds no usable key for the principal")
        kdcs = _kdcs(login, client.realm)
        ex = AsExchange(client, password=login.password, keys=keys, clock=clock)
        out = ex.process(_ask(kdcs, ex.request(), timeout))
        if isinstance(out, bytes):
            out = ex.process(_ask(kdcs, out, timeout))
        if not isinstance(out, Credential):
            raise KerberosError("AS exchange did not complete")
        tgt = out
    else:
        path = os.fspath(login.ccache) if login.ccache is not None else default_ccache_path()
        try:
            with open(path, "rb") as fh:
                default, creds = read_ccache(fh.read())
        except FileNotFoundError as e:
            raise KerberosError("no Kerberos credential cache found; run kinit first") from e
        client = Principal.parse(login.principal) if login.principal else default
        for c in creds:
            if _same(c.client, client) and _same(c.server, service) and _valid(c, now):
                return c
        tgs_name = Principal(("krbtgt", service.realm), client.realm)
        tgt_or_none = next(
            (
                c
                for c in creds
                if _same(c.client, client) and _same(c.server, tgs_name) and _valid(c, now)
            ),
            None,
        )
        if tgt_or_none is None:
            raise KerberosError(
                "the credential cache holds no valid ticket-granting ticket for the realm"
            )
        tgt = tgt_or_none
        kdcs = _kdcs(login, client.realm)
    if service.realm.upper() != tgt.client.realm.upper():
        raise KerberosError("cross-realm service tickets are not supported")
    tgs = TgsExchange(tgt, service, clock=clock)
    return tgs.process(_ask(kdcs, tgs.request(), timeout))
