# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# saprfclib — SAP logon language codes
#
# SAP identifies a logon language by a single character (the ABAP SPRAS domain),
# and that single character is what the RFC logon frame carries. Source: golden
# fixture tests/golden/framing/logon_request.bin — TLV tags 0x0115 and 0x0011 each
# hold one ASCII byte, b"E", for a logon in English.
#
# The SAP RFC SDK also accepts the two-character ISO code on its LANG connection
# option, purely as a client-side convenience: it converts anything longer than one
# character to the corresponding one-character SAP code before the logon frame is
# built, and rejects the connection when the code will not map. This module
# reproduces that convenience so callers migrating from the C SDK (or from pyrfc,
# which passes LANG straight through to it) do not have to translate by hand.
#
# Evidence for the mapping below: it was recorded by calling the SDK's own public
# conversion API — RfcLanguageIsoToSap / RfcLanguageSapToIso, exposed by pyrfc as
# language_iso_to_sap / language_sap_to_iso — once per code, and keeping only pairs
# that round-trip in both directions. It is observed behaviour of a public,
# documented interface, gathered for interoperability; no SDK header, table text, or
# decompiler output was copied. The probe itself is not part of this repository: it
# needs the SDK that this project exists to avoid.
#
# Note that the SDK's forward conversion is NOT a validator. Given an unknown
# two-character code it returns a garbage character rather than an error (e.g. "xx"
# yields U+C138), which is why the SDK follows the conversion with a range check.
# The table here was built from the reverse direction and round-trip verified, so an
# unmappable code raises instead of silently producing a wrong logon language.
from __future__ import annotations

__all__ = [
    "language_iso_to_sap",
    "language_sap_to_iso",
    "normalize_logon_language",
]

# One-character SAP language code → two-character ISO code.
# Round-trip verified in both directions; 35 pairs, no mismatches.
_SAP_TO_ISO: dict[str, str] = {
    "A": "AR",  # Arabic
    "B": "HE",  # Hebrew
    "C": "CS",  # Czech
    "D": "DE",  # German
    "E": "EN",  # English
    "F": "FR",  # French
    "G": "EL",  # Greek
    "H": "HU",  # Hungarian
    "I": "IT",  # Italian
    "J": "JA",  # Japanese
    "K": "DA",  # Danish
    "L": "PL",  # Polish
    "M": "ZF",  # Chinese (traditional) — SAP-specific code, not ISO 639-1
    "N": "NL",  # Dutch
    "O": "NO",  # Norwegian
    "P": "PT",  # Portuguese
    "Q": "SK",  # Slovak
    "R": "RU",  # Russian
    "S": "ES",  # Spanish
    "T": "TR",  # Turkish
    "U": "FI",  # Finnish
    "V": "SV",  # Swedish
    "W": "BG",  # Bulgarian
    "X": "LT",  # Lithuanian
    "Y": "LV",  # Latvian
    "0": "SR",  # Serbian
    "1": "ZH",  # Chinese (simplified)
    "2": "TH",  # Thai
    "3": "KO",  # Korean
    "4": "RO",  # Romanian
    "5": "SL",  # Slovenian
    "6": "HR",  # Croatian
    "7": "MS",  # Malay
    "8": "UK",  # Ukrainian
    "9": "ET",  # Estonian
}

_ISO_TO_SAP: dict[str, str] = {iso: sap for sap, iso in _SAP_TO_ISO.items()}


def language_iso_to_sap(iso_code: str) -> str:
    """Convert a two-character ISO language code to its one-character SAP code.

    Mirrors ``RfcLanguageIsoToSap`` in the SAP RFC SDK, with one deliberate
    difference: an unknown code raises instead of returning a garbage character.

    Args:
        iso_code: Two-character ISO code, e.g. ``"EN"``. Case-insensitive.

    Returns:
        The one-character SAP language code, e.g. ``"E"``.

    Raises:
        ValueError: If ``iso_code`` is not exactly two characters, or names no
            known SAP language.
    """
    if not isinstance(iso_code, str):
        raise ValueError(f"ISO language code must be a str, got {type(iso_code).__name__!r}")
    code = iso_code.strip().upper()
    if len(code) != 2:
        raise ValueError(f"ISO language code must be exactly two characters, got {iso_code!r}")
    try:
        return _ISO_TO_SAP[code]
    except KeyError:
        raise ValueError(
            f"unknown ISO language code {iso_code!r}; known codes are "
            f"{', '.join(sorted(_ISO_TO_SAP))}"
        ) from None


def language_sap_to_iso(sap_code: str) -> str:
    """Convert a one-character SAP language code to its two-character ISO code.

    Mirrors ``RfcLanguageSapToIso`` in the SAP RFC SDK.

    Args:
        sap_code: One-character SAP code, e.g. ``"E"``. Case-insensitive.

    Returns:
        The two-character ISO code, e.g. ``"EN"``.

    Raises:
        ValueError: If ``sap_code`` is not exactly one character, or names no
            known SAP language.
    """
    if not isinstance(sap_code, str):
        raise ValueError(f"SAP language code must be a str, got {type(sap_code).__name__!r}")
    code = sap_code.strip().upper()
    if len(code) != 1:
        raise ValueError(f"SAP language code must be exactly one character, got {sap_code!r}")
    try:
        return _SAP_TO_ISO[code]
    except KeyError:
        raise ValueError(
            f"unknown SAP language code {sap_code!r}; known codes are "
            f"{', '.join(sorted(_SAP_TO_ISO))}"
        ) from None


def normalize_logon_language(lang: str) -> str:
    """Return the one-character SAP language code the logon frame should carry.

    Accepts either form, matching the SDK's ``LANG`` connection option:

    * one character — taken as the SAP code and passed through unchanged, with no
      lookup. Custom languages installed on a system are not in any table, and the
      SDK does not validate one-character input either.
    * two characters — treated as an ISO code and converted.

    Args:
        lang: One-character SAP code or two-character ISO code. Case-insensitive.

    Returns:
        The one-character SAP language code, uppercased.

    Raises:
        ValueError: If ``lang`` is neither one nor two characters, is non-ASCII, or
            is a two-character code that names no known SAP language.
    """
    if not isinstance(lang, str):
        raise ValueError(f"lang must be a str, got {type(lang).__name__!r}")
    code = lang.strip().upper()
    if len(code) == 2:
        code = language_iso_to_sap(code)
    elif len(code) != 1:
        raise ValueError(
            f"lang must be a one-character SAP language code or a two-character "
            f"ISO code, got {lang!r}"
        )
    if not code.isascii():
        raise ValueError(f"lang must be an ASCII SAP language code, got {lang!r}")
    return code
