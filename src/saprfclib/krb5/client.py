# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Kerberos 5 AS and TGS exchanges (RFC 4120 section 3.1, 3.3) for a client.

Message building and reply processing are sans-I/O (:class:`AsExchange`,
:class:`TgsExchange`); :func:`kdc_roundtrip` is the only function that touches the
network: one request over TCP with the 4-byte big-endian length prefix of RFC 4120
section 7.2.2.

Pre-authentication is PA-ENC-TIMESTAMP (RFC 4120 5.2.7.2), which is what Active
Directory requires by default. The salt and iteration count always come from the
KDC's ETYPE-INFO2 — never assumed.

Security: passwords, keys and tickets never reach a log record, a ``repr`` or an
exception message.
"""

from __future__ import annotations

import datetime as _dt
import os
import socket
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from asn1crypto import parser as _asn1_parser

from saprfclib.krb5 import crypto
from saprfclib.krb5 import messages as m
from saprfclib.krb5.crypto import Key

__all__ = [
    "AsExchange",
    "Credential",
    "KerberosError",
    "Principal",
    "TgsExchange",
    "kdc_roundtrip",
]

# Key usage numbers: RFC 4120 section 7.5.1.
USAGE_PA_ENC_TIMESTAMP = 1
USAGE_AS_REP_ENC_PART = 3
USAGE_TGS_REQ_AUTH_CKSUM = 6
USAGE_TGS_REQ_AUTHENTICATOR = 7
USAGE_TGS_REP_ENC_PART_SESSION = 8
USAGE_TGS_REP_ENC_PART_SUBKEY = 9
USAGE_AP_REQ_AUTHENTICATOR = 11
USAGE_AP_REP_ENC_PART = 12

# KDC options (RFC 4120 5.4.1): bit 1 forwardable, bit 3 renewable... Only these two
# are requested; bit numbers count from the most significant bit of the 32-bit field.
_KDC_OPT_FORWARDABLE = 1
_KDC_OPT_RENEWABLE = 8
_KDC_OPT_CANONICALIZE = 15

_DEFAULT_ETYPES = (crypto.ENCTYPE_AES256, crypto.ENCTYPE_AES128)
_MAX_REPLY = 1 << 20


class KerberosError(Exception):
    """A KDC refused a request, or a reply failed verification."""

    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Principal:
    """A Kerberos principal: name components, realm and name type."""

    components: tuple[str, ...]
    realm: str
    name_type: int = m.NT_PRINCIPAL

    @classmethod
    def parse(
        cls, text: str, *, default_realm: str | None = None, name_type: int | None = None
    ) -> Principal:
        """``name[/instance]@REALM``. Escapes (RFC 1964 2.1.1) are not supported."""
        if "\\" in text:
            raise ValueError("escaped characters in principal names are not supported")
        name, sep, realm = text.rpartition("@")
        if not sep:
            name, realm = text, default_realm or ""
        if not realm or not name:
            raise ValueError("principal needs a name and a realm")
        parts = tuple(name.split("/"))
        nt = (
            name_type
            if name_type is not None
            else (m.NT_SRV_INST if len(parts) > 1 else m.NT_PRINCIPAL)
        )
        return cls(parts, realm, nt)

    def asn1(self) -> m.PrincipalName:
        return m.PrincipalName({"name_type": self.name_type, "name_string": list(self.components)})

    @classmethod
    def from_asn1(cls, name: m.PrincipalName, realm: str) -> Principal:
        return cls(tuple(name["name_string"].native), realm, name["name_type"].native)

    def __str__(self) -> str:
        return "/".join(self.components) + "@" + self.realm


@dataclass(frozen=True)
class Credential:
    """A ticket plus what the client needs to use it."""

    client: Principal
    server: Principal
    ticket: bytes = field(repr=False)  # DER Ticket, [APPLICATION 1]
    session_key: Key = field(repr=False)
    flags: bytes
    authtime: _dt.datetime
    starttime: _dt.datetime | None
    endtime: _dt.datetime
    renew_till: _dt.datetime | None

    def __repr__(self) -> str:
        return f"Credential(client={self.client}, server={self.server}, <redacted>)"


def _flags(*bits: int) -> bytes:
    v = 0
    for b in bits:
        v |= 1 << (31 - b)
    return v.to_bytes(4, "big")


def _now(clock: Callable[[], float]) -> _dt.datetime:
    return _dt.datetime.fromtimestamp(clock(), _dt.UTC)


def _check_error(reply: bytes) -> m.KrbError | None:
    if reply[:1] == b"\x7e":  # [APPLICATION 30]
        err: m.KrbError = m.KrbError.load(reply)
        return err
    return None


def _error_text(err: m.KrbError) -> str:
    code = err["error_code"].native
    return f"KDC returned error {code}"


def _decode_rep_part(plain: bytes) -> m.EncKDCRepPart:
    # RFC 4120 5.4.2: implementations must accept EncASRepPart or EncTGSRepPart in
    # either reply (Active Directory answers an AS request with tag 25).
    if plain[:1] == b"\x79":
        as_part: m.EncKDCRepPart = m.EncASRepPart.load(plain)
        return as_part
    if plain[:1] == b"\x7a":
        tgs_part: m.EncKDCRepPart = m.EncTGSRepPart.load(plain)
        return tgs_part
    raise KerberosError("KDC reply has an unknown encrypted part")


def _ticket_der(ticket: m.Ticket) -> bytes:
    """DER of a Ticket taken from a reply field, without the field's own [n] tag.

    asn1crypto keeps the enclosing field's explicit tag on a value loaded from a
    field, so its ``dump()`` starts with that tag rather than [APPLICATION 1].
    """
    der = bytes(ticket.dump())
    while der[:1] != b"\x61":
        der = bytes(_asn1_parser.parse(der)[4])
    return der


def _credential(part: m.EncKDCRepPart, client: Principal, ticket: m.Ticket) -> Credential:
    k = part["key"]
    return Credential(
        client=client,
        server=Principal.from_asn1(part["sname"], part["srealm"].native),
        ticket=_ticket_der(ticket),
        session_key=Key(k["keytype"].native, k["keyvalue"].native),
        flags=part["flags"].native,
        authtime=part["authtime"].native,
        starttime=part["starttime"].native,
        endtime=part["endtime"].native,
        renew_till=part["renew_till"].native,
    )


class AsExchange:
    """Obtain a ticket-granting ticket with a password or a long-term key.

    Drive it with :meth:`request` → send → :meth:`process`, repeating while
    :meth:`process` returns a new request (the first round normally comes back
    with PREAUTH_REQUIRED and the salt).
    """

    def __init__(
        self,
        client: Principal,
        *,
        password: str | None = None,
        keys: Sequence[Key] = (),
        etypes: Sequence[int] = _DEFAULT_ETYPES,
        lifetime: _dt.timedelta = _dt.timedelta(hours=10),
        clock: Callable[[], float] | None = None,
        random: Callable[[int], bytes] = os.urandom,
    ) -> None:
        if password is None and not keys:
            raise ValueError("a password or a key is required")
        self._client = client
        self._password = password
        self._keys = {k.enctype: k for k in keys}
        self._etypes = tuple(e for e in etypes if password is not None or e in self._keys)
        if not self._etypes:
            raise ValueError("no usable encryption type")
        self._lifetime = lifetime
        import time

        self._clock = clock or time.time
        self._random = random
        self._nonce = 0
        self._key: Key | None = None
        self._tries = 0

    def _body(self) -> m.KDCReqBody:
        self._nonce = int.from_bytes(self._random(4), "big") & 0x7FFFFFFF
        now = _now(self._clock)
        return m.KDCReqBody(
            {
                "kdc_options": _flags(
                    _KDC_OPT_FORWARDABLE, _KDC_OPT_RENEWABLE, _KDC_OPT_CANONICALIZE
                ),
                "cname": m.PrincipalName(
                    {"name_type": m.NT_PRINCIPAL, "name_string": list(self._client.components)}
                ),
                "realm": self._client.realm,
                "sname": m.PrincipalName(
                    {"name_type": m.NT_SRV_INST, "name_string": ["krbtgt", self._client.realm]}
                ),
                "till": m.KerberosTime.from_datetime(now + self._lifetime),
                "rtime": m.KerberosTime.from_datetime(now + 7 * self._lifetime),
                "nonce": self._nonce,
                "etype": list(self._etypes),
            }
        )

    def _pa_pac(self) -> m.PAData:
        return m.PAData(
            {
                "padata_type": m.PA_PAC_REQUEST,
                "padata_value": m.KerbPaPacRequest({"include_pac": True}).dump(),
            }
        )

    def request(self) -> bytes:
        """The first AS-REQ: no pre-authentication, which asks the KDC for the salt."""
        return bytes(
            m.ASReq(
                {
                    "pvno": 5,
                    "msg_type": m.KRB_AS_REQ,
                    "padata": [self._pa_pac()],
                    "req_body": self._body(),
                }
            ).dump()
        )

    def _preauth_request(self, key: Key) -> bytes:
        now = _now(self._clock)
        ts = m.PAEncTsEnc(
            {"patimestamp": m.KerberosTime.from_datetime(now), "pausec": now.microsecond}
        )
        enc = m.EncryptedData(
            {
                "etype": key.enctype,
                "cipher": crypto.encrypt(
                    key, USAGE_PA_ENC_TIMESTAMP, ts.dump(), random=self._random
                ),
            }
        )
        pa = m.PAData({"padata_type": m.PA_ENC_TIMESTAMP, "padata_value": enc.dump()})
        self._key = key
        return bytes(
            m.ASReq(
                {
                    "pvno": 5,
                    "msg_type": m.KRB_AS_REQ,
                    "padata": [pa, self._pa_pac()],
                    "req_body": self._body(),
                }
            ).dump()
        )

    def _key_from_etype_info(self, e_data: bytes | None) -> Key:
        if not e_data:
            raise KerberosError("KDC requires pre-authentication but sent no salt")
        for pa in m.MethodData.load(e_data):
            if pa["padata_type"].native != m.PA_ETYPE_INFO2:
                continue
            for entry in m.ETypeInfo2.load(pa["padata_value"].native):
                et = entry["etype"].native
                if et not in self._etypes:
                    continue
                if et in self._keys:
                    return self._keys[et]
                assert self._password is not None
                salt = entry["salt"].native
                if salt is None:
                    raise KerberosError("KDC sent no salt for the chosen encryption type")
                params = entry["s2kparams"].native
                it = struct.unpack(">I", params)[0] if params else None
                return crypto.string_to_key(et, self._password, salt.encode("utf-8"), it)
        raise KerberosError("KDC offers no encryption type in common with the client")

    def process(self, reply: bytes) -> bytes | Credential:
        """Return the next request to send, or the TGT once the exchange is done."""
        err = _check_error(reply)
        if err is not None:
            code = err["error_code"].native
            if code == m.KDC_ERR_PREAUTH_REQUIRED and self._key is None and self._tries == 0:
                self._tries += 1
                return self._preauth_request(self._key_from_etype_info(err["e_data"].native))
            raise KerberosError(_error_text(err), code=code)
        rep = m.ASRep.load(reply)
        if self._key is None:
            raise KerberosError("KDC issued a ticket without pre-authentication")
        enc = rep["enc_part"]
        if enc["etype"].native != self._key.enctype:
            raise KerberosError("AS-REP encrypted with an unexpected key")
        try:
            plain = crypto.decrypt(self._key, USAGE_AS_REP_ENC_PART, enc["cipher"].native)
        except crypto.IntegrityError as e:
            raise KerberosError("AS-REP could not be decrypted") from e
        part = _decode_rep_part(plain)
        if part["nonce"].native != self._nonce:
            raise KerberosError("AS-REP nonce mismatch")
        # The KDC may canonicalize the client name (requested above); use its answer.
        client = Principal.from_asn1(rep["cname"], rep["crealm"].native)
        return _credential(part, client, rep["ticket"])


class TgsExchange:
    """Obtain a service ticket with a TGT (RFC 4120 3.3)."""

    def __init__(
        self,
        tgt: Credential,
        server: Principal,
        *,
        etypes: Sequence[int] = _DEFAULT_ETYPES,
        clock: Callable[[], float] | None = None,
        random: Callable[[int], bytes] = os.urandom,
    ) -> None:
        import time

        self._tgt = tgt
        self._server = server
        self._etypes = tuple(etypes)
        self._clock = clock or time.time
        self._random = random
        self._nonce = 0

    def request(self) -> bytes:
        self._nonce = int.from_bytes(self._random(4), "big") & 0x7FFFFFFF
        now = _now(self._clock)
        body = m.KDCReqBody(
            {
                "kdc_options": _flags(
                    _KDC_OPT_FORWARDABLE, _KDC_OPT_RENEWABLE, _KDC_OPT_CANONICALIZE
                ),
                "realm": self._server.realm,
                "sname": self._server.asn1(),
                "till": m.KerberosTime.from_datetime(self._tgt.endtime),
                "nonce": self._nonce,
                "etype": list(self._etypes),
            }
        )
        key = self._tgt.session_key
        ctype, cval = crypto.checksum(key, USAGE_TGS_REQ_AUTH_CKSUM, body.dump())
        auth = m.Authenticator(
            {
                "authenticator_vno": 5,
                "crealm": self._tgt.client.realm,
                "cname": self._tgt.client.asn1(),
                "cksum": {"cksumtype": ctype, "checksum": cval},
                "cusec": now.microsecond,
                "ctime": m.KerberosTime.from_datetime(now),
            }
        )
        ap = m.APReq(
            {
                "pvno": 5,
                "msg_type": m.KRB_AP_REQ,
                "ap_options": _flags(),
                "ticket": m.Ticket.load(self._tgt.ticket),
                "authenticator": {
                    "etype": key.enctype,
                    "cipher": crypto.encrypt(
                        key, USAGE_TGS_REQ_AUTHENTICATOR, auth.dump(), random=self._random
                    ),
                },
            }
        )
        pa = m.PAData({"padata_type": m.PA_TGS_REQ, "padata_value": ap.dump()})
        return bytes(
            m.TGSReq(
                {"pvno": 5, "msg_type": m.KRB_TGS_REQ, "padata": [pa], "req_body": body}
            ).dump()
        )

    def process(self, reply: bytes) -> Credential:
        err = _check_error(reply)
        if err is not None:
            raise KerberosError(_error_text(err), code=err["error_code"].native)
        rep = m.TGSRep.load(reply)
        enc = rep["enc_part"]
        key = self._tgt.session_key
        if enc["etype"].native != key.enctype:
            raise KerberosError("TGS-REP encrypted with an unexpected key")
        try:
            plain = crypto.decrypt(key, USAGE_TGS_REP_ENC_PART_SESSION, enc["cipher"].native)
        except crypto.IntegrityError as e:
            raise KerberosError("TGS-REP could not be decrypted") from e
        part = _decode_rep_part(plain)
        if part["nonce"].native != self._nonce:
            raise KerberosError("TGS-REP nonce mismatch")
        client = Principal.from_asn1(rep["cname"], rep["crealm"].native)
        return _credential(part, client, rep["ticket"])


def kdc_roundtrip(kdc: tuple[str, int], request: bytes, *, timeout: float = 10.0) -> bytes:
    """Send one request to a KDC over TCP and return the reply (RFC 4120 7.2.2)."""
    with socket.create_connection(kdc, timeout=timeout) as s:
        s.sendall(struct.pack(">I", len(request)) + request)
        hdr = _recv_exact(s, 4)
        (n,) = struct.unpack(">I", hdr)
        if n & 0x80000000 or n > _MAX_REPLY:
            raise KerberosError("KDC reply length out of range")
        return _recv_exact(s, n)


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise KerberosError("KDC closed the connection")
        buf += chunk
    return bytes(buf)
