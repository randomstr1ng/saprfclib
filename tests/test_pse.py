# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""PSE reader against golden PSE files created and exported by sapgenpse."""

import json
import pathlib

import pytest
from asn1crypto import keys

from saprfclib.pse import PseError, load_pse

GOLDEN = pathlib.Path(__file__).parent / "golden" / "pse"
CASES = sorted(p.stem for p in GOLDEN.glob("*.pse"))


def _fixture(name: str) -> tuple[bytes, dict]:
    return (GOLDEN / f"{name}.pse").read_bytes(), json.loads((GOLDEN / f"{name}.json").read_text())


def _rsa_numbers(der: bytes) -> tuple[int, int]:
    try:
        info = keys.PrivateKeyInfo.load(der)
        rsa = info["private_key"].parsed
    except ValueError:
        rsa = keys.RSAPrivateKey.load(der)
    return rsa["modulus"].native, rsa["private_exponent"].native


def test_cases_present():
    assert len(CASES) >= 4


@pytest.mark.parametrize("name", CASES)
def test_pse_matches_sapgenpse_export(name):
    data, exp = _fixture(name)
    cred = load_pse(data, exp["pin"])
    n_ref, d_ref = _rsa_numbers(bytes.fromhex(exp["private_key_pkcs8"]))
    n, d = _rsa_numbers(cred.private_key)
    assert n == n_ref
    # Equivalent private exponents may differ by a multiple of lambda(n); check by use.
    assert pow(pow(12345, 65537, n), d, n) == 12345
    assert pow(pow(12345, 65537, n), d_ref, n) == 12345
    assert [c.hex() for c in cred.certificate_chain] == exp["certificates_from_export"]
    assert [c.hex() for c in cred.trusted] == exp["trusted"]


@pytest.mark.parametrize("name", [c for c in CASES if "nopin" not in c])
def test_wrong_pin_is_rejected(name):
    data, _ = _fixture(name)
    with pytest.raises(PseError):
        load_pse(data, "not-the-pin")


@pytest.mark.parametrize("name", [c for c in CASES if "nopin" not in c])
def test_missing_pin_is_rejected(name):
    data, _ = _fixture(name)
    with pytest.raises(PseError, match="PIN"):
        load_pse(data, None)


def test_error_messages_never_contain_the_pin():
    data, _ = _fixture("pse_v2_pbe_3des")
    with pytest.raises(PseError) as ei:
        load_pse(data, "SECRET-PIN-VALUE")
    assert "SECRET-PIN-VALUE" not in str(ei.value)


@pytest.mark.parametrize("blob", [b"", b"\x30\x00", b"\x30\x03\x02\x01\x07", b"\x04\x02ab"])
def test_garbage_is_rejected(blob):
    with pytest.raises(PseError):
        load_pse(blob, None)


def test_credential_repr_is_redacted():
    data, exp = _fixture("pse_v2_pbe_3des")
    cred = load_pse(data, exp["pin"])
    assert repr(cred) == "SncCredential(<redacted>)"
