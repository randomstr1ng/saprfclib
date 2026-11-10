# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Kerberos 5 message types (RFC 4120 section 5) as ``asn1crypto`` definitions.

Only the messages a client needs: AS and TGS exchanges, AP-REQ/AP-REP and KRB-ERROR,
plus the pre-authentication data Active Directory uses (PA-ENC-TIMESTAMP,
ETYPE-INFO2). The module definition uses EXPLICIT tags throughout, so every
context and application tag here is explicit.
"""

from __future__ import annotations

import datetime as _dt

from asn1crypto import core

# Message type numbers: RFC 4120 section 7.5.7.
KRB_AS_REQ = 10
KRB_AS_REP = 11
KRB_TGS_REQ = 12
KRB_TGS_REP = 13
KRB_AP_REQ = 14
KRB_AP_REP = 15
KRB_ERROR = 30

# Pre-authentication data types: RFC 4120 section 7.5.2, RFC 6806, MS-KILE 2.2.
PA_TGS_REQ = 1
PA_ENC_TIMESTAMP = 2
PA_ETYPE_INFO2 = 19
PA_PAC_REQUEST = 128  # MS-KILE 2.2.3

# Principal name types: RFC 4120 section 6.2.
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_ENTERPRISE = 10

# Error codes used by the client: RFC 4120 section 7.5.9.
KDC_ERR_PREAUTH_REQUIRED = 25
KRB_AP_ERR_SKEW = 37


class KerberosString(core.GeneralString):
    pass


class Realm(KerberosString):
    pass


class Int32(core.Integer):
    pass


class UInt32(core.Integer):
    pass


class Microseconds(core.Integer):
    pass


class KerberosTime(core.GeneralizedTime):
    """GeneralizedTime without fractional seconds, always UTC (RFC 4120 5.2.3)."""

    @classmethod
    def from_datetime(cls, when: _dt.datetime) -> KerberosTime:
        return cls(when.astimezone(_dt.UTC).replace(microsecond=0))


class KerberosFlags(core.OctetBitString):
    """A 32-bit flag field. RFC 4120 5.2.8 requires at least 32 bits on the wire,
    which a named BIT STRING with trailing zero bits removed would violate."""


class SequenceOfKerberosString(core.SequenceOf):
    _child_spec = KerberosString


class PrincipalName(core.Sequence):
    _fields = [
        ("name_type", Int32, {"explicit": 0}),
        ("name_string", SequenceOfKerberosString, {"explicit": 1}),
    ]


class EncryptedData(core.Sequence):
    _fields = [
        ("etype", Int32, {"explicit": 0}),
        ("kvno", UInt32, {"explicit": 1, "optional": True}),
        ("cipher", core.OctetString, {"explicit": 2}),
    ]


class EncryptionKey(core.Sequence):
    _fields = [
        ("keytype", Int32, {"explicit": 0}),
        ("keyvalue", core.OctetString, {"explicit": 1}),
    ]


class Checksum(core.Sequence):
    _fields = [
        ("cksumtype", Int32, {"explicit": 0}),
        ("checksum", core.OctetString, {"explicit": 1}),
    ]


class Ticket(core.Sequence):
    explicit = (1, 1)  # [APPLICATION 1]
    _fields = [
        ("tkt_vno", core.Integer, {"explicit": 0}),
        ("realm", Realm, {"explicit": 1}),
        ("sname", PrincipalName, {"explicit": 2}),
        ("enc_part", EncryptedData, {"explicit": 3}),
    ]


class SequenceOfTicket(core.SequenceOf):
    _child_spec = Ticket


class HostAddress(core.Sequence):
    _fields = [
        ("addr_type", Int32, {"explicit": 0}),
        ("address", core.OctetString, {"explicit": 1}),
    ]


class HostAddresses(core.SequenceOf):
    _child_spec = HostAddress


class AuthorizationDataEntry(core.Sequence):
    _fields = [
        ("ad_type", Int32, {"explicit": 0}),
        ("ad_data", core.OctetString, {"explicit": 1}),
    ]


class AuthorizationData(core.SequenceOf):
    _child_spec = AuthorizationDataEntry


class PAData(core.Sequence):
    _fields = [
        ("padata_type", Int32, {"explicit": 1}),
        ("padata_value", core.OctetString, {"explicit": 2}),
    ]


class MethodData(core.SequenceOf):
    _child_spec = PAData


class SequenceOfInt32(core.SequenceOf):
    _child_spec = Int32


class KDCReqBody(core.Sequence):
    _fields = [
        ("kdc_options", KerberosFlags, {"explicit": 0}),
        ("cname", PrincipalName, {"explicit": 1, "optional": True}),
        ("realm", Realm, {"explicit": 2}),
        ("sname", PrincipalName, {"explicit": 3, "optional": True}),
        ("from", KerberosTime, {"explicit": 4, "optional": True}),
        ("till", KerberosTime, {"explicit": 5}),
        ("rtime", KerberosTime, {"explicit": 6, "optional": True}),
        ("nonce", UInt32, {"explicit": 7}),
        ("etype", SequenceOfInt32, {"explicit": 8}),
        ("addresses", HostAddresses, {"explicit": 9, "optional": True}),
        ("enc_authorization_data", EncryptedData, {"explicit": 10, "optional": True}),
        ("additional_tickets", SequenceOfTicket, {"explicit": 11, "optional": True}),
    ]


class _KDCReq(core.Sequence):
    _fields = [
        ("pvno", core.Integer, {"explicit": 1}),
        ("msg_type", core.Integer, {"explicit": 2}),
        ("padata", MethodData, {"explicit": 3, "optional": True}),
        ("req_body", KDCReqBody, {"explicit": 4}),
    ]


class ASReq(_KDCReq):
    explicit = (1, 10)


class TGSReq(_KDCReq):
    explicit = (1, 12)


class _KDCRep(core.Sequence):
    _fields = [
        ("pvno", core.Integer, {"explicit": 0}),
        ("msg_type", core.Integer, {"explicit": 1}),
        ("padata", MethodData, {"explicit": 2, "optional": True}),
        ("crealm", Realm, {"explicit": 3}),
        ("cname", PrincipalName, {"explicit": 4}),
        ("ticket", Ticket, {"explicit": 5}),
        ("enc_part", EncryptedData, {"explicit": 6}),
    ]


class ASRep(_KDCRep):
    explicit = (1, 11)


class TGSRep(_KDCRep):
    explicit = (1, 13)


class LastReqEntry(core.Sequence):
    _fields = [
        ("lr_type", Int32, {"explicit": 0}),
        ("lr_value", KerberosTime, {"explicit": 1}),
    ]


class LastReq(core.SequenceOf):
    _child_spec = LastReqEntry


class EncKDCRepPart(core.Sequence):
    _fields = [
        ("key", EncryptionKey, {"explicit": 0}),
        ("last_req", LastReq, {"explicit": 1}),
        ("nonce", UInt32, {"explicit": 2}),
        ("key_expiration", KerberosTime, {"explicit": 3, "optional": True}),
        ("flags", KerberosFlags, {"explicit": 4}),
        ("authtime", KerberosTime, {"explicit": 5}),
        ("starttime", KerberosTime, {"explicit": 6, "optional": True}),
        ("endtime", KerberosTime, {"explicit": 7}),
        ("renew_till", KerberosTime, {"explicit": 8, "optional": True}),
        ("srealm", Realm, {"explicit": 9}),
        ("sname", PrincipalName, {"explicit": 10}),
        ("caddr", HostAddresses, {"explicit": 11, "optional": True}),
        ("encrypted_pa_data", MethodData, {"explicit": 12, "optional": True}),
    ]


class EncASRepPart(EncKDCRepPart):
    explicit = (1, 25)


class EncTGSRepPart(EncKDCRepPart):
    explicit = (1, 26)


class APReq(core.Sequence):
    explicit = (1, 14)
    _fields = [
        ("pvno", core.Integer, {"explicit": 0}),
        ("msg_type", core.Integer, {"explicit": 1}),
        ("ap_options", KerberosFlags, {"explicit": 2}),
        ("ticket", Ticket, {"explicit": 3}),
        ("authenticator", EncryptedData, {"explicit": 4}),
    ]


class Authenticator(core.Sequence):
    explicit = (1, 2)
    _fields = [
        ("authenticator_vno", core.Integer, {"explicit": 0}),
        ("crealm", Realm, {"explicit": 1}),
        ("cname", PrincipalName, {"explicit": 2}),
        ("cksum", Checksum, {"explicit": 3, "optional": True}),
        ("cusec", Microseconds, {"explicit": 4}),
        ("ctime", KerberosTime, {"explicit": 5}),
        ("subkey", EncryptionKey, {"explicit": 6, "optional": True}),
        ("seq_number", UInt32, {"explicit": 7, "optional": True}),
        ("authorization_data", AuthorizationData, {"explicit": 8, "optional": True}),
    ]


class APRep(core.Sequence):
    explicit = (1, 15)
    _fields = [
        ("pvno", core.Integer, {"explicit": 0}),
        ("msg_type", core.Integer, {"explicit": 1}),
        ("enc_part", EncryptedData, {"explicit": 2}),
    ]


class EncAPRepPart(core.Sequence):
    explicit = (1, 27)
    _fields = [
        ("ctime", KerberosTime, {"explicit": 0}),
        ("cusec", Microseconds, {"explicit": 1}),
        ("subkey", EncryptionKey, {"explicit": 2, "optional": True}),
        ("seq_number", UInt32, {"explicit": 3, "optional": True}),
    ]


class KrbError(core.Sequence):
    explicit = (1, 30)
    _fields = [
        ("pvno", core.Integer, {"explicit": 0}),
        ("msg_type", core.Integer, {"explicit": 1}),
        ("ctime", KerberosTime, {"explicit": 2, "optional": True}),
        ("cusec", Microseconds, {"explicit": 3, "optional": True}),
        ("stime", KerberosTime, {"explicit": 4}),
        ("susec", Microseconds, {"explicit": 5}),
        ("error_code", Int32, {"explicit": 6}),
        ("crealm", Realm, {"explicit": 7, "optional": True}),
        ("cname", PrincipalName, {"explicit": 8, "optional": True}),
        ("realm", Realm, {"explicit": 9}),
        ("sname", PrincipalName, {"explicit": 10}),
        ("e_text", KerberosString, {"explicit": 11, "optional": True}),
        ("e_data", core.OctetString, {"explicit": 12, "optional": True}),
    ]


class PAEncTsEnc(core.Sequence):
    _fields = [
        ("patimestamp", KerberosTime, {"explicit": 0}),
        ("pausec", Microseconds, {"explicit": 1, "optional": True}),
    ]


class ETypeInfo2Entry(core.Sequence):
    _fields = [
        ("etype", Int32, {"explicit": 0}),
        ("salt", KerberosString, {"explicit": 1, "optional": True}),
        ("s2kparams", core.OctetString, {"explicit": 2, "optional": True}),
    ]


class ETypeInfo2(core.SequenceOf):
    _child_spec = ETypeInfo2Entry


class KerbPaPacRequest(core.Sequence):
    """MS-KILE 2.2.3 KERB-PA-PAC-REQUEST."""

    _fields = [("include_pac", core.Boolean, {"explicit": 0})]
