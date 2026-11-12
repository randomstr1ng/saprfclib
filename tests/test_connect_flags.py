# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Yes/no connection parameters are read as booleans, never by truthiness (issue #64).

``snc_sso="0"`` used to count as *on*: the password was dropped and the logon used the
SNC identity instead. The NW RFC SDK spellings ``"1"``/``"0"`` (what pyrfc callers
pass) are accepted; anything else is refused before any connection is opened.
"""

from __future__ import annotations

import asyncio

import pytest

import saprfclib
from saprfclib import connection as connmod


@pytest.mark.parametrize(
    "value,expected",
    [(True, True), (False, False), (1, True), (0, False), ("1", True), ("0", False), (" 1 ", True)],
)
def test_flag_accepts_bool_and_sdk_forms(value, expected):
    assert connmod._flag("x", value) is expected


@pytest.mark.parametrize("value", ["false", "true", "yes", "", "2", 2, -1, None, 1.0, [1]])
def test_flag_refuses_everything_else(value):
    with pytest.raises(TypeError, match="x must be True or False"):
        connmod._flag("x", value)


class _Stop(Exception):
    pass


@pytest.fixture
def no_network(monkeypatch):
    def _tcp(*a, **k):
        raise _Stop

    monkeypatch.setattr(connmod, "connect_tcp", _tcp)


BASE = {"ashost": "h", "sysnr": "00", "client": "001", "user": "u", "passwd": "SECRET-PW"}


@pytest.mark.parametrize(
    "kw",
    [
        {"snc_sso": "false"},
        {"snc_kerberos": "no"},
        {"ws_tls_verify": "off"},
        {"strict_params": "yes"},
        {"allow_restricted_logon": 2},
        {"ms_use_http": "true"},
    ],
)
def test_connect_refuses_ambiguous_flags_before_connecting(no_network, kw):
    with pytest.raises(TypeError, match="must be True or False"):
        saprfclib.connect(**BASE, **kw)


@pytest.mark.parametrize("kw", [{"snc_sso": "false"}, {"snc_kerberos": "no"}])
def test_connect_async_refuses_ambiguous_flags(kw):
    with pytest.raises(TypeError, match="must be True or False"):
        asyncio.run(saprfclib.connect_async(**BASE, **kw))


def test_snc_sso_string_zero_keeps_the_password(no_network, caplog):
    # "0" is off: no SNC-identity logon, so the password is kept and no SNC is needed.
    with pytest.raises(_Stop):
        saprfclib.connect(**BASE, snc_sso="0")
    assert "password is ignored" not in caplog.text
    assert "SECRET-PW" not in caplog.text


def test_snc_sso_string_one_means_sso(no_network):
    # "1" is on, and SSO without SNC is refused as before.
    with pytest.raises(ValueError, match="needs SNC"):
        saprfclib.connect(**BASE, snc_sso="1")
