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


# --- cred_v2 (sapgenpse seclogin) and local protected storage ------------------

from saprfclib.pse import (  # noqa: E402
    cred_pin,
    load_secudir_credential,
    pin_for_pse,
    read_cred_v2,
)

CRED_FORMS = ["simple", "aes", "uid", "lps"]


def _cred(form):
    d = GOLDEN / f"cred_{form}"
    return (d / "cred_v2").read_bytes(), json.loads((d / "cred_v2.json").read_text())


@pytest.mark.parametrize("form", CRED_FORMS)
def test_cred_v2_pin_recovered(form):
    data, exp = _cred(form)
    (entry,) = read_cred_v2(data)
    assert entry.pse_path == "/secudir/client.pse"
    assert cred_pin(entry, exp["os_user"]) == exp["pin"]


@pytest.mark.parametrize("form", ["simple", "aes", "uid"])
def test_cred_v2_bound_to_user_name(form):
    data, _ = _cred(form)
    (entry,) = read_cred_v2(data)
    with pytest.raises(PseError, match="user"):
        cred_pin(entry, "someone-else")


def test_cred_repr_hides_blob():
    data, _ = _cred("simple")
    (entry,) = read_cred_v2(data)
    assert entry.blob.hex() not in repr(entry)


def _der(tag, content):
    n = len(content)
    ln = (
        bytes([n])
        if n < 128
        else bytes([0x81, n])
        if n < 256
        else bytes([0x82]) + n.to_bytes(2, "big")
    )
    return bytes([tag]) + ln + content


def _with_path(data: bytes, new_path: bytes) -> bytes:
    """Re-encode a cred_v2 file with every stored PSE path replaced."""

    def kids(b):
        out, i = [], 0
        while i < len(b):
            t, n, j = b[i], b[i + 1], i + 2
            if n & 0x80:
                k = n & 0x7F
                n, j = int.from_bytes(b[j : j + k], "big"), j + k
            out.append((t, b[j : j + n]))
            i = j + n
        return out

    ((outer_tag, outer),) = kids(data)
    entries = []
    for t, v in kids(outer):
        fields = [_der(ft, new_path if fv.endswith(b"client.pse") else fv) for ft, fv in kids(v)]
        entries.append(_der(t, b"".join(fields)))
    return _der(outer_tag, b"".join(entries))


def _secudir(tmp_path, form, pse_name="client.pse"):
    data, _ = _cred(form)
    (tmp_path / pse_name).write_bytes((GOLDEN / "pse_v2_pbe_3des.pse").read_bytes())
    (tmp_path / "cred_v2").write_bytes(_with_path(data, str(tmp_path / pse_name).encode()))
    return tmp_path


@pytest.mark.parametrize("form", CRED_FORMS)
def test_secudir_discovery_and_pin_for_pse(tmp_path, form):
    _, exp = _cred(form)
    d = _secudir(tmp_path, form)
    ref = load_pse((GOLDEN / "pse_v2_pbe_3des.pse").read_bytes(), "test123")
    cred = load_secudir_credential(d, user=exp["os_user"])
    assert cred.certificate == ref.certificate
    assert pin_for_pse(d / "client.pse", d, user=exp["os_user"]) == "test123"


def test_secudir_selects_by_myname(tmp_path):
    d = _secudir(tmp_path, "simple")
    ok = load_secudir_credential(d, myname="p:cn=LAB-RSA-V2,o=lab,c=DE", user="fixtureuser")
    assert ok.certificate
    with pytest.raises(PseError, match="no usable"):
        load_secudir_credential(d, myname="p:CN=other", user="fixtureuser")


def test_secudir_falls_back_to_unprotected_sapsncs(tmp_path):
    (tmp_path / "SAPSNCS.pse").write_bytes((GOLDEN / "pse_v4_nopin.pse").read_bytes())
    cred = load_secudir_credential(tmp_path)
    assert (
        cred.certificate == load_pse((GOLDEN / "pse_v4_nopin.pse").read_bytes(), None).certificate
    )


def test_empty_secudir_is_reported(tmp_path):
    with pytest.raises(PseError, match="no usable"):
        load_secudir_credential(tmp_path)


def test_lps_record_tamper_is_detected():
    data = bytearray((GOLDEN / "pse_v2_lps.pse").read_bytes())
    data[60] ^= 1
    with pytest.raises(PseError):
        load_pse(bytes(data), "test123")
