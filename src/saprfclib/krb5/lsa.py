# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Service tickets from the Windows logon session (single sign-on).

Windows keeps the Kerberos tickets of a logon session inside LSA, not in a file. A
process can ask LSA for a service ticket, together with its session key, with
``LsaCallAuthenticationPackage`` and the ``KerbRetrieveEncodedTicketMessage``
request of the Kerberos authentication package. LSA answers from its cache or asks
the KDC with the logon session's ticket-granting ticket, so no password and no KDC
address are needed.

API and structure layouts: Microsoft Win32 documentation, ``NTSecAPI.h``
(``KERB_RETRIEVE_TKT_REQUEST``, ``KERB_RETRIEVE_TKT_RESPONSE``,
``KERB_EXTERNAL_TICKET``, ``KERB_EXTERNAL_NAME``, ``KERB_CRYPTO_KEY``). The calls go
through ``ctypes`` to ``secur32.dll``, which is part of Windows.

Windows returns the session key of a service ticket to the session's own
processes; only the key of the ticket-granting ticket is withheld by default
(``AllowTgtSessionKey``), and this module never asks for that one.

Security: the session key and ticket go into the returned
:class:`~saprfclib.krb5.client.Credential` only, never into a log or exception
message.
"""

from __future__ import annotations

import ctypes
import datetime as _dt
import sys
from ctypes import wintypes
from typing import Any

from saprfclib.krb5.client import Credential, KerberosError, Principal
from saprfclib.krb5.crypto import ENCTYPE_AES128, ENCTYPE_AES256, Key

__all__ = ["lsa_available", "retrieve_service_ticket"]

# KERB_PROTOCOL_MESSAGE_TYPE: KerbRetrieveEncodedTicketMessage (NTSecAPI.h).
_KERB_RETRIEVE_ENCODED_TICKET_MESSAGE = 8
# KERB_RETRIEVE_TICKET_CACHE_TICKET (NTSecAPI.h): keep a ticket LSA had to request
# in the logon session's cache, as any other Kerberos client on the machine would.
_KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20
# Windows FILETIME epoch: 100 ns intervals since 1601-01-01 UTC.
_FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC)


# Windows' USHORT/ULONG/LONG are 16/32/32 bits on every Windows target; fixed-width
# ctypes keep that layout (and its offline test) the same on any host.


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_void_p),
    ]


class _LsaString(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_char_p),
    ]


class _Luid(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]


class _SecHandle(ctypes.Structure):
    _fields_ = [("dwLower", ctypes.c_size_t), ("dwUpper", ctypes.c_size_t)]


class _RetrieveTktRequest(ctypes.Structure):
    _fields_ = [
        ("MessageType", ctypes.c_int),
        ("LogonId", _Luid),
        ("TargetName", _UnicodeString),
        ("TicketFlags", ctypes.c_uint32),
        ("CacheOptions", ctypes.c_uint32),
        ("EncryptionType", ctypes.c_int32),
        ("CredentialsHandle", _SecHandle),
    ]


class _CryptoKey(ctypes.Structure):
    _fields_ = [
        ("KeyType", ctypes.c_int32),
        ("Length", ctypes.c_uint32),
        ("Value", ctypes.c_void_p),
    ]


class _ExternalTicket(ctypes.Structure):
    _fields_ = [
        ("ServiceName", ctypes.c_void_p),
        ("TargetName", ctypes.c_void_p),
        ("ClientName", ctypes.c_void_p),
        ("DomainName", _UnicodeString),
        ("TargetDomainName", _UnicodeString),
        ("AltTargetDomainName", _UnicodeString),
        ("SessionKey", _CryptoKey),
        ("TicketFlags", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("KeyExpirationTime", ctypes.c_longlong),
        ("StartTime", ctypes.c_longlong),
        ("EndTime", ctypes.c_longlong),
        ("RenewUntil", ctypes.c_longlong),
        ("TimeSkew", ctypes.c_longlong),
        ("EncodedTicketSize", ctypes.c_uint32),
        ("EncodedTicket", ctypes.c_void_p),
    ]


class _ExternalNameHeader(ctypes.Structure):
    # KERB_EXTERNAL_NAME: NameType, NameCount, then NameCount UNICODE_STRINGs.
    _fields_ = [("NameType", ctypes.c_short), ("NameCount", ctypes.c_uint16)]


def lsa_available() -> bool:
    """True on Windows, where the logon session's tickets can be asked for."""
    return sys.platform == "win32"


def _unicode(us: _UnicodeString) -> str:
    if not us.Buffer or not us.Length:
        return ""
    return ctypes.wstring_at(us.Buffer, us.Length // 2)


def _external_name(ptr: int | None, realm: str) -> Principal:
    if not ptr:
        raise KerberosError("LSA returned a ticket without a name")
    hdr = _ExternalNameHeader.from_address(ptr)
    first = ptr + ctypes.sizeof(ctypes.c_void_p)  # Names[] is pointer-aligned
    names = tuple(
        _unicode(_UnicodeString.from_address(first + i * ctypes.sizeof(_UnicodeString)))
        for i in range(hdr.NameCount)
    )
    return Principal(names, realm, hdr.NameType)


def _filetime(v: int) -> _dt.datetime | None:
    if v <= 0 or v >= 0x7FFFFFFFFFFFFFFF:
        return None
    return _FILETIME_EPOCH + _dt.timedelta(microseconds=v // 10)


def _ntstatus_text(status: int) -> str:
    advapi: Any = ctypes.WinDLL("advapi32")  # type: ignore[attr-defined]  # Windows only
    err = advapi.LsaNtStatusToWinError(ctypes.c_uint32(status & 0xFFFFFFFF))
    return f"0x{status & 0xFFFFFFFF:08X} ({ctypes.FormatError(err).strip()})"  # type: ignore[attr-defined]  # Windows only


def retrieve_service_ticket(service: Principal) -> Credential:
    """Ask LSA for a ticket to ``service`` in the current logon session.

    Only AES enctypes are requested, in the order AES256, AES128.
    Raises :class:`KerberosError` when LSA has no ticket and cannot get one.
    """
    if not lsa_available():
        raise KerberosError("the Windows logon session is only available on Windows")
    secur32: Any = ctypes.WinDLL("secur32")  # type: ignore[attr-defined]  # Windows only

    handle = wintypes.HANDLE()
    status = secur32.LsaConnectUntrusted(ctypes.byref(handle))
    if status < 0:
        raise KerberosError(f"LsaConnectUntrusted failed: {_ntstatus_text(status)}")
    try:
        pkg_name = b"Kerberos"
        pkg = _LsaString(len(pkg_name), len(pkg_name) + 1, pkg_name)
        pkg_id = ctypes.c_uint32()
        status = secur32.LsaLookupAuthenticationPackage(
            handle, ctypes.byref(pkg), ctypes.byref(pkg_id)
        )
        if status < 0:
            raise KerberosError(f"Kerberos package not found: {_ntstatus_text(status)}")

        target = str(service)
        name = target.encode("utf-16-le")
        # LSA reads the target name only from inside the submitted buffer, so the
        # request is followed directly by the name it points to (an untrusted
        # caller's pointers outside that buffer are rejected as invalid).
        size = ctypes.sizeof(_RetrieveTktRequest) + len(name)
        errors: list[str] = []
        for etype in (ENCTYPE_AES256, ENCTYPE_AES128):
            buf = ctypes.create_string_buffer(size)
            req = _RetrieveTktRequest.from_buffer(buf)
            name_addr = ctypes.addressof(buf) + ctypes.sizeof(_RetrieveTktRequest)
            ctypes.memmove(name_addr, name, len(name))
            req.MessageType = _KERB_RETRIEVE_ENCODED_TICKET_MESSAGE
            req.TargetName = _UnicodeString(len(name), len(name), name_addr)
            req.CacheOptions = _KERB_RETRIEVE_TICKET_CACHE_TICKET
            req.EncryptionType = etype
            out = ctypes.c_void_p()
            out_len = ctypes.c_uint32()
            sub = ctypes.c_int32()
            status = secur32.LsaCallAuthenticationPackage(
                handle,
                pkg_id,
                buf,
                size,
                ctypes.byref(out),
                ctypes.byref(out_len),
                ctypes.byref(sub),
            )
            try:
                if status < 0 or sub.value < 0:
                    errors.append(_ntstatus_text(status if status < 0 else sub.value))
                    continue
                if not out.value:
                    errors.append("empty reply")
                    continue
                return _credential(_ExternalTicket.from_address(out.value))
            finally:
                if out.value:
                    secur32.LsaFreeReturnBuffer(out)
        raise KerberosError(f"Windows could not get a ticket for {target}: " + "; ".join(errors))
    finally:
        secur32.LsaDeregisterLogonProcess(handle)


def _credential(t: _ExternalTicket) -> Credential:
    key_type = int(t.SessionKey.KeyType)
    if key_type not in (ENCTYPE_AES256, ENCTYPE_AES128):
        raise KerberosError(f"LSA returned a session key of unsupported type {key_type}")
    if not t.SessionKey.Value or not t.EncodedTicket:
        raise KerberosError("LSA returned a ticket without its session key")
    key = Key(key_type, ctypes.string_at(t.SessionKey.Value, t.SessionKey.Length))
    ticket = ctypes.string_at(t.EncodedTicket, t.EncodedTicketSize)
    client_realm = _unicode(t.DomainName)
    service_realm = _unicode(t.TargetDomainName) or client_realm
    start = _filetime(t.StartTime)
    return Credential(
        client=_external_name(t.ClientName, client_realm),
        server=_external_name(t.ServiceName, service_realm),
        ticket=ticket,
        session_key=key,
        flags=int(t.TicketFlags).to_bytes(4, "big"),
        authtime=start or _dt.datetime.fromtimestamp(0, _dt.UTC),
        starttime=start,
        endtime=_filetime(t.EndTime) or _dt.datetime.fromtimestamp(0, _dt.UTC),
        renew_till=_filetime(t.RenewUntil),
    )
