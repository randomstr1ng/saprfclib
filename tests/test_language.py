# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Logon language code handling (issue #8).

The RFC logon frame carries a one-character SAP language code — golden fixture
tests/golden/framing/logon_request.bin holds b"E" on TLV tags 0x0115 and 0x0011.
The SDK additionally accepts a two-character ISO code on its LANG option and
converts it before building the frame; saprfclib.language reproduces that.

The offline tests here pin the mapping and the accept/reject behaviour. The
integration test at the bottom cross-checks the table against the SDK itself via
pyrfc, and is skipped wherever the SDK is not installed.
"""

from __future__ import annotations

import pytest

from saprfclib.language import (
    _SAP_TO_ISO,
    language_iso_to_sap,
    language_sap_to_iso,
    normalize_logon_language,
)

# --------------------------------------------------------------------------- #
# Mapping
# --------------------------------------------------------------------------- #


def test_mapping_round_trips_in_both_directions() -> None:
    """Every pair converts back to itself — the property the table was built on."""
    for sap, iso in _SAP_TO_ISO.items():
        assert language_sap_to_iso(sap) == iso
        assert language_iso_to_sap(iso) == sap


def test_mapping_is_a_bijection() -> None:
    """No two SAP codes may share an ISO code, or iso_to_sap would be ambiguous."""
    assert len(set(_SAP_TO_ISO.values())) == len(_SAP_TO_ISO)


@pytest.mark.parametrize(
    ("iso", "sap"),
    [
        ("EN", "E"),
        ("DE", "D"),
        ("ES", "S"),  # not "E" — no first-letter rule exists
        ("EL", "G"),  # Greek
        ("DA", "K"),  # Danish
        ("FI", "U"),  # Finnish
        ("ZH", "1"),  # digits are valid SAP codes
        ("KO", "3"),
    ],
)
def test_known_pairs(iso: str, sap: str) -> None:
    """Spot-check the pairs that disprove any guessable rule."""
    assert language_iso_to_sap(iso) == sap
    assert language_sap_to_iso(sap) == iso


def test_conversion_is_case_insensitive() -> None:
    assert language_iso_to_sap("en") == "E"
    assert language_sap_to_iso("e") == "EN"


def test_unknown_iso_code_raises_rather_than_returning_garbage() -> None:
    """Deliberate divergence from the SDK.

    The SDK's forward conversion is not a validator: given an unknown two-character
    code it returns a garbage character (``"xx"`` yields U+C138) and relies on a
    follow-up range check to notice. Raising is the safer contract — a wrong logon
    language is silent otherwise.
    """
    with pytest.raises(ValueError, match="unknown ISO language code"):
        language_iso_to_sap("xx")


def test_unknown_sap_code_raises() -> None:
    with pytest.raises(ValueError, match="unknown SAP language code"):
        language_sap_to_iso("#")


@pytest.mark.parametrize("bad", ["E", "ENG", "", "   "])
def test_iso_to_sap_requires_exactly_two_characters(bad: str) -> None:
    with pytest.raises(ValueError, match="exactly two characters"):
        language_iso_to_sap(bad)


@pytest.mark.parametrize("bad", ["EN", "", "   "])
def test_sap_to_iso_requires_exactly_one_character(bad: str) -> None:
    with pytest.raises(ValueError, match="exactly one character"):
        language_sap_to_iso(bad)


def test_non_str_input_raises_valueerror_not_typeerror() -> None:
    with pytest.raises(ValueError, match="must be a str"):
        language_iso_to_sap(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="must be a str"):
        language_sap_to_iso(5)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# normalize_logon_language — what the logon frame actually gets
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("E", "E"),  # SAP code passes through
        ("e", "E"),  # uppercased
        ("EN", "E"),  # ISO converted
        ("en", "E"),
        ("DE", "D"),
        ("ES", "S"),
        (" EN ", "E"),  # surrounding whitespace tolerated
    ],
)
def test_normalize_accepts_both_forms(given: str, expected: str) -> None:
    assert normalize_logon_language(given) == expected


def test_one_character_input_is_not_validated_against_the_table() -> None:
    """SDK parity: the SDK only converts input longer than one character.

    A system can have custom languages that appear in no table, so a
    one-character code is taken at face value.
    """
    assert normalize_logon_language("Z") == "Z"


@pytest.mark.parametrize("bad", ["", "ENG", "ENGLISH"])
def test_normalize_rejects_wrong_length(bad: str) -> None:
    with pytest.raises(ValueError, match="one-character SAP language code"):
        normalize_logon_language(bad)


def test_normalize_rejects_unknown_iso_code() -> None:
    with pytest.raises(ValueError, match="unknown ISO language code"):
        normalize_logon_language("xx")


def test_normalize_rejects_non_ascii() -> None:
    with pytest.raises(ValueError, match="ASCII"):
        normalize_logon_language("é")


def test_helpers_are_exported_from_the_package_root() -> None:
    """pyrfc exposes the same two names; migrating callers should find them here."""
    import saprfclib

    assert saprfclib.language_iso_to_sap("EN") == "E"
    assert saprfclib.language_sap_to_iso("E") == "EN"


# --------------------------------------------------------------------------- #
# Cross-check against the SDK itself (needs pyrfc + the NW RFC SDK)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_mapping_matches_the_sdk() -> None:
    """Verify every pair against RfcLanguageIsoToSap / RfcLanguageSapToIso.

    This is the probe the table was built from, kept as a test so the mapping stays
    reproducible for anyone holding the SDK. Deselected in CI, which has no SDK.
    """
    pyrfc = pytest.importorskip("pyrfc", reason="needs pyrfc + the SAP NW RFC SDK")

    mismatches = []
    for sap, iso in _SAP_TO_ISO.items():
        if pyrfc.language_sap_to_iso(sap) != iso:
            mismatches.append(f"sap_to_iso({sap!r}) != {iso!r}")
        if pyrfc.language_iso_to_sap(iso) != sap:
            mismatches.append(f"iso_to_sap({iso!r}) != {sap!r}")
    assert not mismatches, f"table diverges from the SDK: {mismatches}"
