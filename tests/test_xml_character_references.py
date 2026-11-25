# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Character references and entities in BASXML (ET_DATA) text (#74).

What the server sends is replayed from
tests/golden/serialization/basxml_character_references.json. The rest follows the
XML 1.0 grammar: a reference is decided by its value at any zero-padded width,
anything that is not a Unicode scalar value is refused, and so is anything that is
not well-formed.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from saprfclib.invoke import _XML_REF_MAX_DIGITS, _xml_unescape, decode_basxml_table

FX = json.loads(
    (
        pathlib.Path(__file__).parent
        / "golden"
        / "serialization"
        / "basxml_character_references.json"
    ).read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", FX["values"], ids=lambda c: c["value"][:30])
def test_captured_rows_decode_as_the_reference_client_returned_them(case: dict) -> None:
    doc = b"<ET_DATA>" + bytes.fromhex(case["item_hex"]) + b"</ET_DATA>"
    assert decode_basxml_table(doc, "ET_DATA") == [{"LINE": case["value"]}]


SCALARS = st.integers(min_value=0, max_value=0x10FFFF).filter(lambda c: not 0xD800 <= c <= 0xDFFF)


@given(SCALARS, st.integers(min_value=0, max_value=_XML_REF_MAX_DIGITS))
def test_a_reference_decodes_the_same_at_every_padded_width(code: int, width: int) -> None:
    dec, hexa = str(code), format(code, "x")
    assert _xml_unescape(f"&#{dec.rjust(min(width, _XML_REF_MAX_DIGITS), '0')};") == chr(code)
    assert _xml_unescape(f"&#x{hexa.rjust(min(width, _XML_REF_MAX_DIGITS), '0')};") == chr(code)
    assert _xml_unescape(f"&#x{hexa.upper()};") == chr(code)


@pytest.mark.parametrize("text", ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"])
def test_the_five_predefined_entities(text: str) -> None:
    assert (
        _xml_unescape(f"a{text}b")
        == "a" + {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'"}[text] + "b"
    )


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("&#xD800;", "scalar"),  # surrogate
        ("&#57343;", "scalar"),  # 0xDFFF
        ("&#x110000;", "scalar"),  # above U+10FFFF
        ("a & b", "malformed XML"),  # bare ampersand
        ("&#;", "malformed"),
        ("&#x;", "malformed"),
        ("&#12a;", "malformed"),
        ("&#X41;", "malformed"),  # only a lower-case x introduces hex in XML
        ("&nbsp;", "unknown XML entity"),
        ("&#" + "0" * (_XML_REF_MAX_DIGITS + 1) + "65;", "malformed XML"),  # over-long run
        ("&#65", "malformed XML"),  # unterminated
    ],
)
def test_refused_forms(text: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        _xml_unescape(text)


def test_invalid_utf8_is_refused_not_replaced() -> None:
    with pytest.raises(ValueError, match="not valid UTF-8"):
        decode_basxml_table(b"<T><item><L>\xc3</L></item></T>", "T")


@given(st.text(max_size=200))
def test_arbitrary_text_decodes_or_raises_valueerror(text: str) -> None:
    try:
        out = _xml_unescape(text)
    except ValueError:
        return
    assert isinstance(out, str)
    assert not any(0xD800 <= ord(c) <= 0xDFFF for c in out if c not in text)
