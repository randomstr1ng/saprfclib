# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Deep parameters as XML text (tags 0x3c02 / 0x3c05) -- sans-I/O.

A parameter whose type is a structure with a STRING, XSTRING or table component, or
a table-typed IMPORTING / EXPORTING / CHANGING parameter (with flat rows or not), does
not travel as a fixed-width buffer. Both the reference client and the server send it
as one XML element per parameter, UTF-8, between two empty 0x3c02 records::

    0x3c02 ""   0x3c05 "<IS_DEEP><ID>1</ID><STR>d1</STR>...</IS_DEEP>"   0x3c02 ""

TABLES parameters, flat structures and scalars (including a top-level STRING) stay on
the binary path in the same call.

Everything below is taken from live captures of the reference client (pyrfc 3.3.1 on
the NW RFC SDK 7.50) against ABAP Platform 2025 (kernel 916), calling STFC_DEEP_STRUCTURE,
STFC_DEEP_TABLE and a purpose-built echo module whose deep structure holds every
scalar type, a nested flat structure, a nested deep structure, a nested table of flat
rows and a nested table of deep rows. The fixtures are under
tests/golden/serialization/deep_*; docs/protocol/serialization.md has the details.

Value forms (client and server agree unless noted):

=========== ======================================================================
CHAR        the text, trailing blanks dropped (``Ab <&>``)
NUMC        all digits, zero-padded to the field width (``000042``)
DATS        ``YYYY-MM-DD``; the server writes an initial date as ``0000-00-00``
TIMS        ``HH:MM:SS``
DEC         plain decimal with the field's decimals (``-1234.56``, ``0.00``)
FLTP        the server writes ``1.5000000000000000E+00``; the client sent ``1.5``
INT1..INT8  decimal integer
RAW         base64 of the field's bytes (``AP8QIA==``)
STRING      the text
XSTRING     base64 (``AAH/3q0=``); empty is an empty element
DECFLOAT    plain decimal (``12.5``, ``-0.001``)
UTCLONG     the signed 64-bit value of the binary form, as a decimal integer
structure   one element per component, in layout order
table       one ``<item>`` per row; an empty table is an empty element
=========== ======================================================================

Escaping: the client writes ``&``, ``<`` and ``>`` as ``&#38;``, ``&#60;``, ``&#62;``
and every other character, controls and non-ASCII included, as itself. The server
additionally escapes ``"`` and ``'``. A large value is cut into 0x3c05 records of
16384 bytes (a 2000-row table of 230 KB, all records but the last exactly that size).
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import struct
from collections.abc import Iterable, Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from .codec import (
    RFCTYPE_BCD,
    RFCTYPE_BYTE,
    RFCTYPE_CHAR,
    RFCTYPE_DATE,
    RFCTYPE_DECF16,
    RFCTYPE_DECF34,
    RFCTYPE_FLOAT,
    RFCTYPE_INT,
    RFCTYPE_INT1,
    RFCTYPE_INT2,
    RFCTYPE_INT8,
    RFCTYPE_NUM,
    RFCTYPE_STRING,
    RFCTYPE_STRUCTURE,
    RFCTYPE_TABLE,
    RFCTYPE_TIME,
    RFCTYPE_UTCLONG,
    RFCTYPE_XSTRING,
    _default_field_value,
    decode,
    encode,
)
from .types import RFC_TABLES, FieldDesc, TypeDesc

__all__ = [
    "XML_CHUNK_BYTES",
    "decode_xml_parameter",
    "encode_xml_parameter",
    "is_deep",
    "travels_as_xml",
]

# Size of each 0x3c05 record the reference client writes for a long value: every
# record of a 230 KB table but the last was 16384 bytes (live capture, 2026-11-26).
XML_CHUNK_BYTES = 16384

# Bounds on input the peer controls (trust boundary T-04-RESP). Not wire values.
_MAX_XML_BYTES = 64 * 1024 * 1024
_MAX_ITEMS = 1_000_000
_MAX_DEPTH = 66  # the same bound invoke.snapshot_params applies to arguments

# The tag a table row travels under (every capture).
_ROW_TAG = "item"

# Component names the element syntax can carry. A DDIC name may also contain "/"
# (a namespace, /ABC/FIELD); how such a name is written as an element has not been
# captured, and writing it as it is would produce a closing tag that ends the wrong
# element, so it is refused rather than guessed.
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# Escapes the reference client writes (see the module docstring).
_ESCAPES = (("&", "&#38;"), ("<", "&#60;"), (">", "&#62;"))

_INT_TYPES = frozenset({RFCTYPE_INT, RFCTYPE_INT1, RFCTYPE_INT2, RFCTYPE_INT8})
_DEEP_COMPONENT_TYPES = frozenset({RFCTYPE_STRING, RFCTYPE_XSTRING, RFCTYPE_TABLE})

_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})\Z")
_TIME_RE = re.compile(r"(\d{2}):(\d{2}):(\d{2})\Z")
_INT_RE = re.compile(r"[+-]?\d+\Z")


# --------------------------------------------------------------------------- #
# Which parameters travel as XML
# --------------------------------------------------------------------------- #


def is_deep(type_desc: TypeDesc, _depth: int = 0) -> bool:
    """True if a structure has a STRING, XSTRING or table component at any depth."""
    if _depth > _MAX_DEPTH:
        raise ValueError(f"type {type_desc.name!r} is nested deeper than {_MAX_DEPTH} levels")
    for child in type_desc.fields:
        if child.rfctype in _DEEP_COMPONENT_TYPES:
            return True
        if (
            child.rfctype == RFCTYPE_STRUCTURE
            and child.type_desc is not None
            and is_deep(child.type_desc, _depth + 1)
        ):
            return True
    return False


def travels_as_xml(field: FieldDesc) -> bool:
    """True if this top-level parameter is sent and returned as XML.

    A table-typed parameter outside TABLES always is, even with flat rows: sent as
    a binary table, the server refuses it with CALL_FUNCTION_ILLEGAL_P_TYPE (live,
    2026-11-26), and the reference client sends it as XML. A structure is XML
    exactly when it is deep. TABLES parameters keep the binary table protocol.
    """
    if field.direction == RFC_TABLES:
        return False
    if field.rfctype == RFCTYPE_TABLE:
        return True
    return (
        field.rfctype == RFCTYPE_STRUCTURE
        and field.type_desc is not None
        and is_deep(field.type_desc)
    )


# --------------------------------------------------------------------------- #
# Encoding
# --------------------------------------------------------------------------- #


def _escape(text: str) -> str:
    for raw, ref in _ESCAPES:
        text = text.replace(raw, ref)
    return text


def _element_name(field: FieldDesc, path: str) -> str:
    if not _NAME_RE.match(field.name):
        raise NotImplementedError(
            f"{path}: the name {field.name!r} cannot be written as an XML element; how "
            "the server spells a namespaced name in a deep parameter has not been "
            "captured (docs/protocol/serialization.md, Known Gaps)"
        )
    return field.name


def _require_layout(field: FieldDesc, path: str) -> TypeDesc:
    if field.type_desc is None:
        from .exceptions import IncompleteDescriptorError

        raise IncompleteDescriptorError(
            f"{path}: the layout of {field.name!r} was never resolved, so it cannot "
            "be written or read as XML"
        )
    return field.type_desc


def _scalar_text(field: FieldDesc, value: Any, path: str) -> str:
    """The text of one scalar component, normalised through the binary codec.

    Running a value through the codec first gives it the same validation, padding
    and truncation it gets on the binary path, so a value means the same thing in a
    flat structure as in a deep one.
    """
    rfctype = field.rfctype
    try:
        if rfctype == RFCTYPE_STRING:
            return _escape(str(value).split("\x00", 1)[0])
        if rfctype == RFCTYPE_XSTRING:
            return base64.b64encode(bytes(value)).decode("ascii")
        if rfctype == RFCTYPE_BYTE:
            raw = bytes(value)
            width = field.uc_length if field.unicode_mode else field.nuc_length
            if width and len(raw) > width:
                raise ValueError(f"{len(raw)} bytes do not fit RAW({width})")
            # RAW is fixed-width: the server returns a short value zero-filled to
            # the field's width (initial RAW(4) comes back as AAAAAA==).
            return base64.b64encode(raw.ljust(width, b"\x00")).decode("ascii")
        canonical = decode(rfctype, encode(rfctype, value, field), field)
    except (TypeError, ValueError, InvalidOperation) as exc:
        raise type(exc)(f"{path}: {exc}") from exc
    if rfctype == RFCTYPE_CHAR:
        return _escape(str(canonical))
    if rfctype == RFCTYPE_NUM:
        return str(canonical)
    if rfctype == RFCTYPE_DATE:
        # An initial date is written as the server writes one, 0000-00-00, and read
        # back as initial (echo probe, 2026-11-26). The reference client was not
        # captured sending one: it refuses an empty date before sending.
        d = str(canonical) or "00000000"
        return f"{d[:4]}-{d[4:6]}-{d[6:8]}"
    if rfctype == RFCTYPE_TIME:
        t = str(canonical) or "000000"
        return f"{t[:2]}:{t[2:4]}:{t[4:6]}"
    if rfctype == RFCTYPE_BCD:
        return format(Decimal(canonical), "f")
    if rfctype in (RFCTYPE_DECF16, RFCTYPE_DECF34):
        # Exponent notation where Decimal uses it, so the scale survives: 1E+5 and
        # 1.20E-7 came back as sent, where the plain form turned 1E+5 into 100000
        # (echo probe, 2026-11-26). The binary path keeps the scale the same way.
        return str(Decimal(canonical))
    if rfctype == RFCTYPE_FLOAT:
        number = float(canonical)
        if not math.isfinite(number):
            raise ValueError(f"{path}: {number!r} has no ABAP float representation")
        # The form the server writes. It also reads it: 1.5 and -1e-300 came back
        # exactly (echo probe, 2026-11-26).
        return f"{number:.16E}"
    if rfctype in _INT_TYPES:
        return str(int(canonical))
    if rfctype == RFCTYPE_UTCLONG:
        (ticks,) = struct.unpack("<q", encode(rfctype, value, field))
        return str(ticks)
    raise NotImplementedError(
        f"{path}: RFCTYPE {rfctype} inside a deep parameter has not been captured"
    )


def _value_text(field: FieldDesc, value: Any, path: str, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise ValueError(f"{path}: nested deeper than {_MAX_DEPTH} levels")
    if field.rfctype == RFCTYPE_STRUCTURE:
        return _structure_text(_require_layout(field, path), value, path, depth)
    if field.rfctype == RFCTYPE_TABLE:
        layout = _require_layout(field, path)
        if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
            raise TypeError(f"{path}: a table takes a list of rows, not {type(value).__name__}")
        return "".join(
            f"<{_ROW_TAG}>{_structure_text(layout, row, f'{path}[{i}]', depth + 1)}</{_ROW_TAG}>"
            for i, row in enumerate(value)
        )
    return _scalar_text(field, value, path)


def _structure_text(layout: TypeDesc, value: Any, path: str, depth: int) -> str:
    if not isinstance(value, Mapping):
        raise TypeError(f"{path}: a structure takes a dict, not {type(value).__name__}")
    supplied = {str(k).upper(): v for k, v in value.items()}
    parts: list[str] = []
    for child in layout.fields:
        name = _element_name(child, path)
        child_value = supplied.get(child.name.upper(), _MISSING)
        if child_value is _MISSING:
            # Every component is written, as the reference client does when given a
            # value; a component the caller left out gets its type's initial value.
            child_value = _default_field_value(child)
        parts.append(
            f"<{name}>{_value_text(child, child_value, f'{path}-{name}', depth + 1)}</{name}>"
        )
    return "".join(parts)


_MISSING = object()


def encode_xml_parameter(field: FieldDesc, value: Any) -> bytes:
    """The UTF-8 XML document for one deep parameter, wrapper element included."""
    name = _element_name(field, field.name)
    body = _value_text(field, value, field.name, 0)
    return f"<{name}>{body}</{name}>".encode()


# --------------------------------------------------------------------------- #
# Decoding
# --------------------------------------------------------------------------- #


class _Element:
    __slots__ = ("children", "name", "text")

    def __init__(self, name: str) -> None:
        self.name = name
        self.children: list[_Element] = []
        self.text = ""


def _parse(text: str, what: str) -> _Element:
    """Parse elements-with-text-only XML into a tree.

    Deliberately hand-rolled: the payload comes from the peer, and the stdlib
    parsers accept DTDs and entity definitions this grammar never uses (the same
    reasoning as invoke._xml_unescape). Anything outside elements and text -- an
    attribute, a declaration, a comment, mixed text and elements -- is refused.
    """
    from .invoke import _xml_unescape

    root: _Element | None = None
    stack: list[_Element] = []
    pos, n = 0, len(text)
    items = 0
    while pos < n:
        lt = text.find("<", pos)
        if lt == -1:
            lt = n
        chunk = text[pos:lt]
        if chunk:
            if not stack:
                raise ValueError(f"{what}: text outside the root element")
            stack[-1].text += _xml_unescape(chunk)
        if lt == n:
            break
        gt = text.find(">", lt + 1)
        if gt == -1:
            raise ValueError(f"{what}: unterminated tag at offset {lt}")
        tag = text[lt + 1 : gt]
        pos = gt + 1
        if tag.startswith("/"):
            name = tag[1:]
            if not stack or stack[-1].name != name:
                raise ValueError(f"{what}: closing tag </{name}> does not match")
            done = stack.pop()
            if done.children and done.text:
                raise ValueError(f"{what}: element <{name}> mixes text and elements")
            continue
        self_closing = tag.endswith("/")
        name = tag[:-1] if self_closing else tag
        if not _NAME_RE.match(name):
            raise ValueError(f"{what}: unsupported markup <{tag}> at offset {lt}")
        element = _Element(name)
        items += 1
        if items > _MAX_ITEMS:
            raise ValueError(f"{what}: more than {_MAX_ITEMS} elements")
        if stack:
            stack[-1].children.append(element)
        elif root is None:
            root = element
        else:
            raise ValueError(f"{what}: more than one root element")
        if not self_closing:
            if len(stack) >= _MAX_DEPTH + 2:
                raise ValueError(f"{what}: nested deeper than {_MAX_DEPTH} levels")
            stack.append(element)
    if stack:
        raise ValueError(f"{what}: element <{stack[-1].name}> is never closed")
    if root is None:
        raise ValueError(f"{what}: no element")
    return root


def _scalar_value(field: FieldDesc, text: str, path: str) -> Any:
    rfctype = field.rfctype
    try:
        if rfctype == RFCTYPE_STRING:
            return text
        if rfctype in (RFCTYPE_XSTRING, RFCTYPE_BYTE):
            return base64.b64decode(text, validate=True)
        if rfctype == RFCTYPE_CHAR:
            return decode(rfctype, text.encode("utf-16-le"), field)
        if rfctype == RFCTYPE_NUM:
            if text and not text.isdigit():
                raise ValueError(f"{text!r} is not a NUMC value")
            return text
        if rfctype == RFCTYPE_DATE:
            m = _DATE_RE.match(text)
            if m is None:
                raise ValueError(f"{text!r} is not YYYY-MM-DD")
            return decode(rfctype, "".join(m.groups()).encode("utf-16-le"), field)
        if rfctype == RFCTYPE_TIME:
            m = _TIME_RE.match(text)
            if m is None:
                raise ValueError(f"{text!r} is not HH:MM:SS")
            return decode(rfctype, "".join(m.groups()).encode("utf-16-le"), field)
        if rfctype in (RFCTYPE_BCD, RFCTYPE_DECF16, RFCTYPE_DECF34):
            amount = Decimal(text)
            if not amount.is_finite():
                raise ValueError(f"{text!r} is not a finite decimal")
            return amount
        if rfctype == RFCTYPE_FLOAT:
            return float(text)
        if rfctype in _INT_TYPES or rfctype == RFCTYPE_UTCLONG:
            if not _INT_RE.match(text):
                raise ValueError(f"{text!r} is not an integer")
            number = int(text)
            if rfctype == RFCTYPE_UTCLONG:
                return decode(rfctype, struct.pack("<q", number), field)
            return number
    except (ValueError, InvalidOperation, binascii.Error, struct.error) as exc:
        raise ValueError(f"{path}: {exc}") from None
    raise NotImplementedError(
        f"{path}: RFCTYPE {rfctype} inside a deep parameter has not been captured"
    )


def _initial(field: FieldDesc, path: str, depth: int) -> Any:
    """The value of a component the server sent as an empty structure element."""
    if field.rfctype == RFCTYPE_STRUCTURE:
        layout = _require_layout(field, path)
        return {c.name: _initial(c, f"{path}-{c.name}", depth + 1) for c in layout.fields}
    if field.rfctype == RFCTYPE_TABLE:
        return []
    if field.rfctype == RFCTYPE_BYTE:
        return bytes(field.uc_length if field.unicode_mode else field.nuc_length)
    return decode(field.rfctype, encode(field.rfctype, _default_field_value(field), field), field)


def _element_value(field: FieldDesc, element: _Element, path: str, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError(f"{path}: nested deeper than {_MAX_DEPTH} levels")
    if field.rfctype == RFCTYPE_STRUCTURE:
        return _structure_value(_require_layout(field, path), element, path, depth)
    if field.rfctype == RFCTYPE_TABLE:
        layout = _require_layout(field, path)
        if element.text:
            raise ValueError(f"{path}: a table holds <{_ROW_TAG}> elements, not text")
        rows = []
        for i, item in enumerate(element.children):
            if item.name != _ROW_TAG:
                raise ValueError(f"{path}: unexpected <{item.name}> in a table")
            rows.append(_structure_value(layout, item, f"{path}[{i}]", depth + 1))
        return rows
    if element.children:
        raise ValueError(f"{path}: a {field.name!r} value cannot contain elements")
    return _scalar_value(field, element.text, path)


def _structure_value(layout: TypeDesc, element: _Element, path: str, depth: int) -> dict[str, Any]:
    if element.text:
        raise ValueError(f"{path}: a structure holds elements, not text")
    if not element.children:
        # <FLAT></FLAT> is how the reference client sends an untouched component;
        # read it the way the server does, as the initial structure.
        return {c.name: _initial(c, f"{path}-{c.name}", depth + 1) for c in layout.fields}
    by_name = {c.name.upper(): c for c in layout.fields}
    result: dict[str, Any] = {}
    for child in element.children:
        field = by_name.get(child.name.upper())
        if field is None:
            # A component the descriptor does not know: most likely the type changed
            # in the system after its layout was cached (see invalidate_metadata).
            raise ValueError(
                f"{path}: the server sent component {child.name!r}, which the cached "
                f"layout of {layout.name!r} does not have; if the type was changed, "
                "call invalidate_metadata() and retry"
            )
        if field.name in result:
            raise ValueError(f"{path}: component {child.name!r} sent twice")
        result[field.name] = _element_value(field, child, f"{path}-{field.name}", depth + 1)
    missing = [c.name for c in layout.fields if c.name not in result]
    if missing:
        raise ValueError(
            f"{path}: the server sent no {', '.join(missing)}; the cached layout of "
            f"{layout.name!r} may be out of date (invalidate_metadata())"
        )
    return {c.name: result[c.name] for c in layout.fields}


def decode_xml_parameter(field: FieldDesc, payload: bytes) -> Any:
    """Decode the joined 0x3c05 records of one deep parameter into Python values."""
    if len(payload) > _MAX_XML_BYTES:
        raise ValueError(f"{field.name}: XML payload of {len(payload)} bytes is over the cap")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{field.name}: XML payload is not UTF-8 at byte {exc.start}") from None
    root = _parse(text, field.name)
    if root.name.upper() != field.name.upper():
        raise ValueError(f"{field.name}: XML payload is for <{root.name}>")
    return _element_value(field, root, field.name, 0)
