# SPDX-License-Identifier: MPL-2.0
"""Tickets from the Windows logon session (saprfclib.krb5.lsa).

The LSA call itself needs Windows and a domain logon and runs as an integration
test there. Offline, the reply structures are built in memory with the documented
layouts and parsed, and the routing in obtain_service_ticket is checked.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import sys

import pytest

from saprfclib.krb5 import login as loginmod
from saprfclib.krb5 import lsa
from saprfclib.krb5.client import Credential, KerberosError, Principal
from saprfclib.krb5.crypto import Key

REALM = "EXAMPLE.TEST"


def _ustr(text: str, keep: list) -> lsa._UnicodeString:
    buf = ctypes.create_unicode_buffer(text)
    keep.append(buf)
    n = len(text.encode("utf-16-le"))
    return lsa._UnicodeString(n, n + 2, ctypes.cast(buf, ctypes.c_void_p))


def _ext_name(name_type: int, parts: list[str], keep: list) -> int:
    ptr = ctypes.sizeof(ctypes.c_void_p)
    size = ptr + len(parts) * ctypes.sizeof(lsa._UnicodeString)
    raw = ctypes.create_string_buffer(size)
    keep.append(raw)
    hdr = lsa._ExternalNameHeader.from_buffer(raw)
    hdr.NameType, hdr.NameCount = name_type, len(parts)
    for i, p in enumerate(parts):
        us = lsa._UnicodeString.from_buffer(raw, ptr + i * ctypes.sizeof(lsa._UnicodeString))
        src = _ustr(p, keep)
        us.Length, us.MaximumLength, us.Buffer = src.Length, src.MaximumLength, src.Buffer
    return ctypes.addressof(raw)


def _filetime(when: dt.datetime) -> int:
    return int((when - lsa._FILETIME_EPOCH).total_seconds()) * 10_000_000


def _external_ticket(keep: list, *, key_type: int = 18) -> lsa._ExternalTicket:
    key = ctypes.create_string_buffer(b"\x5a" * 32, 32)
    ticket = ctypes.create_string_buffer(b"\x61\x03\x02\x01\x05", 5)
    keep += [key, ticket]
    t = lsa._ExternalTicket()
    t.ServiceName = _ext_name(2, ["SAP", "A4H"], keep)
    t.ClientName = _ext_name(1, ["alice"], keep)
    t.DomainName = _ustr(REALM, keep)
    t.TargetDomainName = _ustr(REALM, keep)
    t.SessionKey.KeyType = key_type
    t.SessionKey.Length = 32
    t.SessionKey.Value = ctypes.addressof(key)
    t.TicketFlags = 0x40A50000
    t.StartTime = _filetime(dt.datetime(2026, 11, 11, 13, 0, tzinfo=dt.UTC))
    t.EndTime = _filetime(dt.datetime(2026, 11, 11, 23, 0, tzinfo=dt.UTC))
    t.RenewUntil = 0x7FFFFFFFFFFFFFFF  # "never"
    t.EncodedTicketSize = 5
    t.EncodedTicket = ctypes.addressof(ticket)
    return t


def test_layouts_match_ntsecapi_on_64_bit():
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        pytest.skip("offsets below are the 64-bit layout")
    # KERB_RETRIEVE_TKT_REQUEST and KERB_EXTERNAL_TICKET, NTSecAPI.h, x64.
    assert ctypes.sizeof(lsa._RetrieveTktRequest) == 0x40
    assert lsa._RetrieveTktRequest.TargetName.offset == 0x10
    assert lsa._RetrieveTktRequest.CacheOptions.offset == 0x24
    assert lsa._RetrieveTktRequest.EncryptionType.offset == 0x28
    assert lsa._ExternalTicket.SessionKey.offset == 0x48
    assert lsa._ExternalTicket.EncodedTicketSize.offset == 0x88
    assert lsa._ExternalTicket.EncodedTicket.offset == 0x90


def test_external_ticket_becomes_a_credential():
    keep: list = []
    cred = lsa._credential(_external_ticket(keep))
    assert str(cred.client) == f"alice@{REALM}"
    assert str(cred.server) == f"SAP/A4H@{REALM}"
    assert cred.server.name_type == 2
    assert cred.session_key == Key(18, b"\x5a" * 32)
    assert cred.ticket == b"\x61\x03\x02\x01\x05"
    assert cred.flags == bytes.fromhex("40a50000")
    assert cred.endtime == dt.datetime(2026, 11, 11, 23, 0, tzinfo=dt.UTC)
    assert cred.renew_till is None
    assert "5a5a" not in repr(cred)


def test_rc4_session_key_is_refused():
    keep: list = []
    with pytest.raises(KerberosError, match="unsupported type 23"):
        lsa._credential(_external_ticket(keep, key_type=23))


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows guard")
def test_retrieve_needs_windows():
    assert not lsa.lsa_available()
    with pytest.raises(KerberosError, match="only available on Windows"):
        lsa.retrieve_service_ticket(Principal.parse(f"SAP/A4H@{REALM}"))


# --- routing in obtain_service_ticket ----------------------------------------------


def _cred(server: str, client: str = f"alice@{REALM}") -> Credential:
    now = dt.datetime(2026, 11, 11, 13, 0, tzinfo=dt.UTC)
    return Credential(
        client=Principal.parse(client),
        server=Principal.parse(server),
        ticket=b"t",
        session_key=Key(18, b"\x01" * 32),
        flags=b"\x00" * 4,
        authtime=now,
        starttime=now,
        endtime=now + dt.timedelta(hours=10),
        renew_till=None,
    )


@pytest.fixture
def windows(monkeypatch):
    asked: list[str] = []
    known: dict[str, Credential] = {}

    def _retrieve(service):
        asked.append(str(service))
        if str(service) in known:
            return known[str(service)]
        raise KerberosError(f"Windows could not get a ticket for {service}: 0xC000018B")

    monkeypatch.setattr(loginmod, "lsa_available", lambda: True)
    monkeypatch.setattr(loginmod, "retrieve_service_ticket", _retrieve)
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    return asked, known


CANDIDATES = [Principal.parse(f"SAP/svc@{REALM}"), Principal.parse(f"svc@{REALM}")]


def test_default_login_on_windows_uses_the_logon_session(windows):
    asked, known = windows
    known[f"svc@{REALM}"] = _cred(f"svc@{REALM}")
    cred = loginmod.obtain_service_ticket(loginmod.KerberosLogin(), CANDIDATES)
    assert str(cred.server) == f"svc@{REALM}"
    assert asked == [f"SAP/svc@{REALM}", f"svc@{REALM}"]


def test_logon_session_failure_names_every_candidate(windows):
    with pytest.raises(KerberosError) as ei:
        loginmod.obtain_service_ticket(loginmod.KerberosLogin(), CANDIDATES)
    assert f"SAP/svc@{REALM}" in str(ei.value) and f"svc@{REALM}" in str(ei.value)


def test_logon_session_of_another_principal_is_refused(windows):
    _, known = windows
    known[f"SAP/svc@{REALM}"] = _cred(f"SAP/svc@{REALM}", client=f"bob@{REALM}")
    with pytest.raises(KerberosError, match="different principal"):
        loginmod.obtain_service_ticket(
            loginmod.KerberosLogin(principal=f"alice@{REALM}"), CANDIDATES
        )


def test_krb5ccname_on_windows_selects_the_file_cache(windows, monkeypatch, tmp_path):
    asked, _ = windows
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{tmp_path / 'missing'}")
    with pytest.raises(KerberosError, match="run kinit"):
        loginmod.obtain_service_ticket(loginmod.KerberosLogin(), CANDIDATES)
    assert asked == []
