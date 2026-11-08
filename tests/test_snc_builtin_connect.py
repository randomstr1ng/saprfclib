# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""connect() wiring for the built-in SNC mechanism (no network)."""

import json
import pathlib

import pytest

import saprfclib
from saprfclib.pse import load_pse

PSE = pathlib.Path(__file__).parent / "golden" / "pse" / "pse_v2_pbe_3des.pse"
PIN = json.loads(PSE.with_suffix(".json").read_text())["pin"]
OWN_NAME = "p:CN=lab-rsa-v2, O=lab, C=DE"


class _Reached(Exception):
    pass


def _factory(seen):
    def factory(host, port):
        seen.append((host, port))
        raise _Reached

    return factory


def test_snc_pse_requires_partner_name():
    with pytest.raises(ValueError, match="snc_partnername"):
        saprfclib.connect(ashost="h", sysnr="00", client="001", snc_pse=PSE, snc_pse_pin=PIN)


def test_snc_pse_and_credential_are_exclusive():
    cred = load_pse(PSE.read_bytes(), PIN)
    with pytest.raises(ValueError, match="exactly one"):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=X",
            snc_pse=PSE,
            snc_pse_pin=PIN,
            snc_credential=cred,
        )


def test_snc_myname_must_match_own_certificate():
    with pytest.raises(ValueError, match="snc_myname"):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=X",
            snc_pse=PSE,
            snc_pse_pin=PIN,
            snc_myname="p:CN=someone-else",
        )


def test_builtin_snc_defaults_to_secure_gateway_port():
    seen: list = []
    with pytest.raises(_Reached):
        saprfclib.connect(
            ashost="h",
            sysnr="07",
            client="001",
            snc_partnername="p:CN=X",
            snc_pse=PSE,
            snc_pse_pin=PIN,
            snc_myname=OWN_NAME,
            socket_factory=_factory(seen),
        )
    assert seen == [("h", 4807)]


def test_builtin_snc_with_credential_object():
    seen: list = []
    with pytest.raises(_Reached):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=X",
            snc_credential=load_pse(PSE.read_bytes(), PIN),
            socket_factory=_factory(seen),
        )
    assert seen == [("h", 4800)]


def test_wrong_pin_surfaces_before_connecting():
    seen: list = []
    with pytest.raises(saprfclib.SncError):
        saprfclib.connect(
            ashost="h",
            sysnr="00",
            client="001",
            snc_partnername="p:CN=X",
            snc_pse=PSE,
            snc_pse_pin="wrong",
            socket_factory=_factory(seen),
        )
    assert seen == []
