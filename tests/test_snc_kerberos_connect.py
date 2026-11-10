# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""connect(snc_kerberos=...) plumbing and service-ticket selection, offline."""

import datetime as dt
import json
import os
import pathlib

import pytest

import saprfclib
import saprfclib.connection as connmod
import saprfclib.krb5.login as loginmod
from saprfclib.krb5 import KerberosLogin
from saprfclib.krb5.client import Credential, KerberosError, Principal
from saprfclib.krb5.crypto import Key
from saprfclib.krb5.login import kdcs_from_krb5_conf, obtain_service_ticket

GOLDEN = pathlib.Path(__file__).parent / "golden" / "krb5"
CCACHE = GOLDEN / "mit_ccache_v4.ccache"
# Inside the fixture's ticket lifetimes (authtime 2026-11-10 16:19:58 UTC, +10 h).
IN_LIFETIME = dt.datetime(2026, 11, 10, 18, 0, tzinfo=dt.UTC).timestamp()


# --- partner name -> service principal ---------------------------------------------


@pytest.mark.parametrize(
    "name,principal",
    [
        ("p:CN=sap-snc@EXAMPLE.TEST", "sap-snc@EXAMPLE.TEST"),
        ("p:CN=SAP/A4H@EXAMPLE.TEST", "SAP/A4H@EXAMPLE.TEST"),
    ],
)
def test_service_principal_from_partner_name(name, principal):
    assert str(connmod.kerberos_service_principal(name)) == principal


@pytest.mark.parametrize(
    "name", ["p:CN=A4H, O=SAP, C=DE", "p:CN=nouserrealm", "p:O=x@EXAMPLE.TEST"]
)
def test_non_kerberos_partner_name_is_rejected(name):
    with pytest.raises(ValueError, match="Kerberos SNC partner name"):
        connmod.kerberos_service_principal(name)


# --- connect() routing -------------------------------------------------------------


def _fake_ticket(client="alice@EXAMPLE.TEST"):
    t0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    return Credential(
        Principal.parse(client),
        Principal.parse("svc@EXAMPLE.TEST"),
        b"\x61\x00",
        Key(18, bytes(32)),
        bytes(4),
        t0,
        t0,
        t0 + dt.timedelta(hours=1),
        None,
    )


@pytest.fixture
def stop_after_mechanism(monkeypatch):
    seen = {}

    def _obtain(login, service, **kw):
        seen["login"], seen["service"] = login, service
        return _fake_ticket()

    class _Stop(Exception):
        pass

    def _tcp(*a, **k):
        raise _Stop

    monkeypatch.setattr(loginmod, "obtain_service_ticket", _obtain)
    monkeypatch.setattr(connmod, "connect_tcp", _tcp)
    return seen, _Stop


@pytest.mark.parametrize(
    "value", [True, KerberosLogin(principal="alice@EXAMPLE.TEST", password="SECRET-PW")]
)
def test_snc_kerberos_builds_the_kerberos_mechanism(stop_after_mechanism, value, caplog):
    seen, stop = stop_after_mechanism
    with pytest.raises(stop):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=svc@EXAMPLE.TEST",
            snc_kerberos=value,
            snc_sso=True,
        )
    assert str(seen["service"]) == "svc@EXAMPLE.TEST"
    assert isinstance(seen["login"], KerberosLogin)
    assert "SECRET-PW" not in caplog.text


def test_snc_myname_must_name_the_ticket_client(stop_after_mechanism):
    _, stop = stop_after_mechanism
    with pytest.raises(stop):  # case-insensitive match passes
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=svc@EXAMPLE.TEST",
            snc_kerberos=True,
            snc_sso=True,
            snc_myname="p:CN=ALICE@EXAMPLE.TEST",
        )
    with pytest.raises(ValueError, match="snc_myname"):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=svc@EXAMPLE.TEST",
            snc_kerberos=True,
            snc_sso=True,
            snc_myname="p:CN=bob@EXAMPLE.TEST",
        )


@pytest.mark.parametrize("other", [{"snc_lib": "/x.so"}, {"snc_pse": "x.pse"}])
def test_snc_kerberos_conflicts_with_other_mechanisms(stop_after_mechanism, other):
    with pytest.raises(ValueError, match="snc_kerberos"):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=svc@EXAMPLE.TEST",
            snc_kerberos=True,
            snc_sso=True,
            **other,
        )


async def test_connect_async_passes_snc_kerberos(monkeypatch):
    got = {}

    def _connect(**kw):
        got.update(kw)
        raise RuntimeError("stop")

    monkeypatch.setattr(connmod, "connect", _connect)
    login = KerberosLogin(ccache="/x")
    with pytest.raises(RuntimeError, match="stop"):
        await saprfclib.connect_async(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=svc@EXAMPLE.TEST",
            snc_kerberos=login,
            snc_sso=True,
        )
    assert got["snc_kerberos"] is login


# --- KerberosLogin and service-ticket selection --------------------------------------


def test_login_argument_rules_and_repr():
    with pytest.raises(ValueError, match="at most one"):
        KerberosLogin(principal="a@B", password="x", keytab="k")
    with pytest.raises(ValueError, match="principal"):
        KerberosLogin(password="x")
    assert "hunter2" not in repr(KerberosLogin(principal="a@B", password="hunter2"))


def test_cached_service_ticket_is_used_without_a_kdc():
    st = obtain_service_ticket(
        KerberosLogin(ccache=CCACHE),
        Principal.parse("service@EXAMPLE-REALM.TEST"),
        clock=lambda: IN_LIFETIME,
    )
    assert str(st.server) == "service@EXAMPLE-REALM.TEST"
    assert (
        len(st.ticket)
        == json.loads((GOLDEN / "mit_ccache_v4.json").read_text())["credentials"][1]["ticket_len"]
    )


def test_tgs_needs_a_kdc_when_the_service_is_not_cached(monkeypatch, tmp_path):
    monkeypatch.setenv("KRB5_CONFIG", str(tmp_path / "missing.conf"))
    with pytest.raises(KerberosError, match="no KDC known for realm EXAMPLE-REALM.TEST"):
        obtain_service_ticket(
            KerberosLogin(ccache=CCACHE),
            Principal.parse("other@EXAMPLE-REALM.TEST"),
            clock=lambda: IN_LIFETIME,
        )


def test_expired_cache_is_not_used():
    later = IN_LIFETIME + 86400
    with pytest.raises(KerberosError, match="no valid ticket-granting ticket"):
        obtain_service_ticket(
            KerberosLogin(ccache=CCACHE),
            Principal.parse("service@EXAMPLE-REALM.TEST"),
            clock=lambda: later,
        )


def test_missing_ccache_says_kinit(tmp_path):
    with pytest.raises(KerberosError, match="kinit"):
        obtain_service_ticket(KerberosLogin(ccache=tmp_path / "none"), Principal.parse("s@R"))


def test_krb5_conf_kdc_entries(tmp_path):
    conf = tmp_path / "krb5.conf"
    conf.write_text(
        "[libdefaults]\n default_realm = EXAMPLE.TEST\n"
        "[realms]\n EXAMPLE.TEST = {\n  kdc = dc1.example.test\n  kdc = dc2.example.test:8888\n"
        "  admin_server = dc1.example.test\n }\n OTHER.TEST = {\n  kdc = x\n }\n"
    )
    assert kdcs_from_krb5_conf("EXAMPLE.TEST", str(conf)) == [
        ("dc1.example.test", 88),
        ("dc2.example.test", 8888),
    ]
    assert kdcs_from_krb5_conf("NONE", str(conf)) == []


# --- live (integration) ----------------------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("SAPRFC_SNC_KRB5_PARTNERNAME"),
    reason="SAPRFC_SNC_KRB5_PARTNERNAME not set — no Kerberos SNC system",
)
def test_live_kerberos_snc_sso_logon():
    login = KerberosLogin(
        principal=os.environ.get("SAPRFC_KRB5_USER"),
        password=os.environ.get("SAPRFC_KRB5_PASSWORD"),
        kdc=os.environ.get("SAPRFC_KRB5_KDC"),
    )
    with saprfclib.connect(
        ashost=os.environ["SAPRFC_ASHOST"],
        sysnr=os.environ.get("SAPRFC_SYSNR", "00"),
        client=os.environ.get("SAPRFC_CLIENT", "001"),
        snc_partnername=os.environ["SAPRFC_SNC_KRB5_PARTNERNAME"],
        snc_kerberos=login,
        snc_sso=True,
    ) as conn:
        assert conn.call("STFC_CONNECTION", REQUTEXT="krb5")["ECHOTEXT"] == "krb5"
